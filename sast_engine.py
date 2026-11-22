import ast
import re
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
        # 1. Прямой вызов eval / exec
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

            # 2. Небезопасная десериализация pickle
            if base == "pickle" and attr in ("load", "loads"):
                self._add(
                    node,
                    "SWARM-002",
                    "CWE-502",
                    "HIGH",
                    f"Небезопасная десериализация через pickle.{attr}()",
                )

            # 3. yaml.load без SafeLoader
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

            # 4. subprocess с shell=True
            if base == "subprocess" and attr in ("run", "Popen", "call", "check_call", "check_output"):
                if self._is_const_bool(self._get_kwarg(node, "shell"), True):
                    self._add(
                        node,
                        "SWARM-004",
                        "CWE-78",
                        "HIGH",
                        f"Вызов subprocess.{attr}() с shell=True допускает инъекцию команд",
                    )

            # 5. Слабые хеши MD5 / SHA1
            if base == "hashlib" and attr in ("md5", "sha1"):
                self._add(
                    node,
                    "SWARM-005",
                    "CWE-328",
                    "MEDIUM",
                    f"Слабый криптографический алгоритм hashlib.{attr}(); используйте sha256+",
                )

            # 6. Отключенная проверка TLS-сертификата
            if base == "requests" and attr in ("get", "post", "put", "delete", "patch", "request"):
                if self._is_const_bool(self._get_kwarg(node, "verify"), False):
                    self._add(
                        node,
                        "SWARM-006",
                        "CWE-295",
                        "MEDIUM",
                        f"Отключена проверка SSL-сертификата (verify=False) в requests.{attr}()",
                    )

            # 7. Динамическая сборка SQL-запроса в execute()
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
        # 8. Захардкоженные секреты и ключи
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


def scan_source(source_code: str, filename: str = "<memory>") -> list[Finding]:
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
    return visitor.findings


def scan_file(file_path: Path) -> list[Finding]:
    return scan_source(file_path.read_text(encoding="utf-8"), str(file_path.name))


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
                            "region": {"startLine": f.line},
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
                        "version": "3.0.0",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }
