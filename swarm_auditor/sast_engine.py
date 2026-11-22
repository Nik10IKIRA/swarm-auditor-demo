import ast
import re
import shlex
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    cwe: str
    severity: str
    message: str
    snippet: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


SECRET_NAME_RE = re.compile(
    r"(api[_-]?key|secret|password|passwd|access[_-]?token|private[_-]?key)",
    re.IGNORECASE,
)
PLACEHOLDER_VALUES = {"", "none", "null", "changeme", "example", "test", "dummy"}


class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, lines: list[str]):
        self.filename = filename
        self.lines = lines
        self.findings: list[Finding] = []

    def _add(self, node: ast.AST, rule_id: str, cwe: str, severity: str, message: str):
        lineno = getattr(node, "lineno", 1)
        snippet = self.lines[lineno - 1].strip() if 0 < lineno <= len(self.lines) else ""
        self.findings.append(
            Finding(
                file=self.filename,
                line=lineno,
                rule_id=rule_id,
                cwe=cwe,
                severity=severity,
                message=message,
                snippet=snippet,
            )
        )

    def _get_kwarg(self, node: ast.Call, name: str):
        for kw in node.keywords:
            if kw.arg == name:
                return kw.value
        return None

    def _is_const_bool(self, node: ast.AST | None, expected: bool) -> bool:
        return isinstance(node, ast.Constant) and node.value is expected

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self._add(
                node,
                "SWARM-001",
                "CWE-95",
                "HIGH",
                f"Опасное динамическое выполнение кода через {node.func.id}()",
            )

        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            base = node.func.value.id if isinstance(node.func.value, ast.Name) else ""

            if base == "pickle" and attr in ("load", "loads"):
                self._add(
                    node,
                    "SWARM-002",
                    "CWE-502",
                    "HIGH",
                    f"Небезопасная десериализация через pickle.{attr}()",
                )

            if base == "yaml" and attr == "load":
                loader = self._get_kwarg(node, "Loader")
                loader_name = ""
                if isinstance(loader, ast.Attribute):
                    loader_name = loader.attr
                elif isinstance(loader, ast.Name):
                    loader_name = loader.id
                if loader_name not in ("SafeLoader", "CSafeLoader"):
                    self._add(
                        node,
                        "SWARM-003",
                        "CWE-502",
                        "HIGH",
                        "Вызов yaml.load() без SafeLoader; используйте yaml.safe_load()",
                    )

            if base == "subprocess" and attr in ("run", "Popen", "call", "check_call", "check_output"):
                if self._is_const_bool(self._get_kwarg(node, "shell"), True):
                    self._add(
                        node,
                        "SWARM-004",
                        "CWE-78",
                        "HIGH",
                        f"Вызов subprocess.{attr}() с shell=True допускает инъекцию команд",
                    )

            if base == "hashlib" and attr in ("md5", "sha1"):
                self._add(
                    node,
                    "SWARM-005",
                    "CWE-328",
                    "MEDIUM",
                    f"Слабый криптографический алгоритм hashlib.{attr}(); используйте sha256+",
                )

            if base == "requests" and attr in ("get", "post", "put", "delete", "patch", "request"):
                if self._is_const_bool(self._get_kwarg(node, "verify"), False):
                    self._add(
                        node,
                        "SWARM-006",
                        "CWE-295",
                        "MEDIUM",
                        f"Отключена проверка SSL-сертификата (verify=False) в requests.{attr}()",
                    )

            if attr in ("execute", "executemany") and node.args:
                first_arg = node.args[0]
                is_fstring = isinstance(first_arg, ast.JoinedStr)
                is_concat = isinstance(first_arg, ast.BinOp) and isinstance(
                    first_arg.op, (ast.Add, ast.Mod)
                )
                is_format = (
                    isinstance(first_arg, ast.Call)
                    and isinstance(first_arg.func, ast.Attribute)
                    and first_arg.func.attr == "format"
                )
                if is_fstring or is_concat or is_format:
                    self._add(
                        node,
                        "SWARM-007",
                        "CWE-89",
                        "HIGH",
                        "SQL-запрос формируется через интерполяцию/конкатенацию; используйте параметризацию",
                    )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value.strip()
            if len(val) >= 8 and val.lower() not in PLACEHOLDER_VALUES and not val.startswith("os.getenv"):
                for target in node.targets:
                    if isinstance(target, ast.Name) and SECRET_NAME_RE.search(target.id):
                        self._add(
                            node,
                            "SWARM-008",
                            "CWE-798",
                            "HIGH",
                            f"Обнаружен возможный захардкоженный секрет в переменной '{target.id}'",
                        )
        self.generic_visit(node)


class SecurityASTPatcher(ast.NodeTransformer):
    """Точечный AST-трансформер для гарантированного устранения SAST-уязвимостей."""

    def __init__(self, target_lines: set[int], active_rules: set[str]):
        self.target_lines = target_lines
        self.active_rules = active_rules
        self.needed_imports: set[str] = set()

    def _in_scope(self, node: ast.AST, rule_id: str) -> bool:
        lineno = getattr(node, "lineno", -1)
        return rule_id in self.active_rules and (not self.target_lines or lineno in self.target_lines)

    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)

        # SWARM-001: eval(...) -> ast.literal_eval(...)
        if isinstance(node.func, ast.Name) and node.func.id == "eval" and self._in_scope(node, "SWARM-001"):
            self.needed_imports.add("ast")
            node.func = ast.Attribute(
                value=ast.Name(id="ast", ctx=ast.Load()),
                attr="literal_eval",
                ctx=ast.Load(),
            )
            return node

        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            base = node.func.value.id if isinstance(node.func.value, ast.Name) else ""

            # SWARM-002: pickle.load(s) -> json.load(s)
            if base == "pickle" and attr in ("load", "loads") and self._in_scope(node, "SWARM-002"):
                self.needed_imports.add("json")
                node.func.value = ast.Name(id="json", ctx=ast.Load())
                return node

            # SWARM-003: yaml.load(...) -> yaml.safe_load(...)
            if base == "yaml" and attr == "load" and self._in_scope(node, "SWARM-003"):
                node.func.attr = "safe_load"
                node.keywords = [kw for kw in node.keywords if kw.arg != "Loader"]
                return node

            # SWARM-004: subprocess.*(..., shell=True) -> shell=False + список аргументов
            if (
                base == "subprocess"
                and attr in ("run", "Popen", "call", "check_call", "check_output")
                and self._in_scope(node, "SWARM-004")
            ):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        kw.value = ast.Constant(value=False)
                        if node.args:
                            first = node.args[0]
                            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                                parts = shlex.split(first.value)
                                node.args[0] = ast.List(
                                    elts=[ast.Constant(value=p) for p in parts],
                                    ctx=ast.Load(),
                                )
                            elif not isinstance(first, ast.List):
                                self.needed_imports.add("shlex")
                                node.args[0] = ast.Call(
                                    func=ast.Attribute(
                                        value=ast.Name(id="shlex", ctx=ast.Load()),
                                        attr="split",
                                        ctx=ast.Load(),
                                    ),
                                    args=[first],
                                    keywords=[],
                                )
                return node

            # SWARM-005: hashlib.md5/sha1 -> hashlib.sha256
            if base == "hashlib" and attr in ("md5", "sha1") and self._in_scope(node, "SWARM-005"):
                node.func.attr = "sha256"
                return node

            # SWARM-006: requests.*(..., verify=False) -> verify=True
            if (
                base == "requests"
                and attr in ("get", "post", "put", "delete", "patch", "request")
                and self._in_scope(node, "SWARM-006")
            ):
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        kw.value = ast.Constant(value=True)
                return node

            # SWARM-007: cursor.execute(f"...{x}...") -> параметризация (?, (x,))
            if attr in ("execute", "executemany") and node.args and self._in_scope(node, "SWARM-007"):
                first = node.args[0]
                if isinstance(first, ast.JoinedStr):
                    sql_parts = []
                    params = []
                    for part in first.values:
                        if isinstance(part, ast.Constant) and isinstance(part.value, str):
                            sql_parts.append(part.value)
                        elif isinstance(part, ast.FormattedValue):
                            sql_parts.append("?")
                            params.append(part.value)
                    node.args = [
                        ast.Constant(value="".join(sql_parts)),
                        ast.Tuple(elts=params, ctx=ast.Load()),
                    ]
                return node

        return node

    def visit_Assign(self, node: ast.Assign):
        self.generic_visit(node)
        if not self._in_scope(node, "SWARM-008"):
            return node
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name) and SECRET_NAME_RE.search(target.id):
                    self.needed_imports.add("os")
                    node.value = ast.Call(
                        func=ast.Attribute(
                            value=ast.Name(id="os", ctx=ast.Load()),
                            attr="getenv",
                            ctx=ast.Load(),
                        ),
                        args=[ast.Constant(value=target.id), ast.Constant(value="")],
                        keywords=[],
                    )
                    break
        return node


def deterministic_sast_fix(source_code: str, findings: list[Finding]) -> str:
    """Применяет AST-патчер к строкам из списка найденных SAST-уязвимостей."""
    tree = ast.parse(source_code)
    target_lines = {f.line for f in findings}
    active_rules = {f.rule_id for f in findings}

    patcher = SecurityASTPatcher(target_lines, active_rules)
    new_tree = patcher.visit(tree)
    ast.fix_missing_locations(new_tree)

    existing_imports = set()
    for node in new_tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                existing_imports.add(alias.name.split(".")[0])

    missing = sorted(patcher.needed_imports - existing_imports)
    for mod_name in reversed(missing):
        new_tree.body.insert(0, ast.Import(names=[ast.alias(name=mod_name)]))
    ast.fix_missing_locations(new_tree)

    return ast.unparse(new_tree) + "\n"


def scan_source(
    source_code: str,
    filename: str = "<memory>",
    ignore_rules: set[str] | None = None,
) -> list[Finding]:
    try:
        tree = ast.parse(source_code)
    except SyntaxError as exc:
        return [
            Finding(
                file=filename,
                line=exc.lineno or 1,
                rule_id="SWARM-000",
                cwe="CWE-000",
                severity="HIGH",
                message=f"Синтаксическая ошибка: {exc.msg}",
            )
        ]

    visitor = SecurityASTVisitor(filename, source_code.splitlines())
    visitor.visit(tree)

    if ignore_rules:
        ignored = {r.upper() for r in ignore_rules}
        return [
            f for f in visitor.findings
            if f.rule_id.upper() not in ignored and f.cwe.upper() not in ignored
        ]
    return visitor.findings


def scan_file(file_path: Path, ignore_rules: set[str] | None = None) -> list[Finding]:
    return scan_source(file_path.read_text(encoding="utf-8"), str(file_path.name), ignore_rules=ignore_rules)


def findings_to_sarif(findings: list[Finding]) -> dict:
    severity_map = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    rules_seen = {}
    results = []

    for f in findings:
        rules_seen[f.rule_id] = {
            "id": f.rule_id,
            "shortDescription": {"text": f"{f.cwe}: Security Rule {f.rule_id}"},
            "properties": {"tags": [f.cwe, "security"]},
        }
        results.append(
            {
                "ruleId": f.rule_id,
                "level": severity_map.get(f.severity, "warning"),
                "message": {"text": f"[{f.cwe}] {f.message}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Enterprise AI Swarm Security Auditor",
                        "version": "3.1.0",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }
