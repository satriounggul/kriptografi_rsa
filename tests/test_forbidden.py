"""
Static Code Audit Test (R-01 to R-04 / QA).
Ensures no forbidden functions or external crypto libraries are used in core/ and server/.
Forbidden:
- pow(a, b, m)
- pow(x, -1, m)
- math.gcd
- Any cryptography library (pycryptodome, cryptography, rsa, hashlib rsa, etc.)
"""

import ast
import os
import unittest

FORBIDDEN_MODULES = {
    "cryptography", "Crypto", "Cryptodome", "rsa", "pycryptodome", "nacl"
}


class ForbiddenFunctionVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.violations = []

    def visit_Import(self, node):
        for alias in node.names:
            base_module = alias.name.split(".")[0]
            if base_module in FORBIDDEN_MODULES:
                self.violations.append(f"{self.filename}:{node.lineno} - Forbidden import '{alias.name}'")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            base_module = node.module.split(".")[0]
            if base_module in FORBIDDEN_MODULES:
                self.violations.append(f"{self.filename}:{node.lineno} - Forbidden import from '{node.module}'")
            if node.module == "math":
                for alias in node.names:
                    if alias.name == "gcd":
                        self.violations.append(f"{self.filename}:{node.lineno} - Forbidden import 'math.gcd'")
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check call to math.gcd(...)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "math" and node.func.attr == "gcd":
                self.violations.append(f"{self.filename}:{node.lineno} - Forbidden call to 'math.gcd'")

        # Check call to built-in pow(...) with 3 arguments or pow(x, -1, m)
        if isinstance(node.func, ast.Name) and node.func.id == "pow":
            if len(node.args) >= 3:
                self.violations.append(f"{self.filename}:{node.lineno} - Forbidden 3-argument call to built-in 'pow(a, b, m)'")
            elif len(node.args) == 2:
                # check if exponent is -1
                if isinstance(node.args[1], ast.UnaryOp) and isinstance(node.args[1].op, ast.USub):
                    self.violations.append(f"{self.filename}:{node.lineno} - Forbidden modular inversion 'pow(x, -1)'")

        self.generic_visit(node)


class TestForbiddenAudit(unittest.TestCase):

    def test_audit_core_and_server(self):
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        target_dirs = ["core", "server"]
        all_violations = []

        for d in target_dirs:
            dir_path = os.path.join(project_root, d)
            if not os.path.exists(dir_path):
                continue
            for root, _, files in os.walk(dir_path):
                for f in files:
                    if f.endswith(".py"):
                        full_path = os.path.join(root, f)
                        with open(full_path, "r", encoding="utf-8") as code_file:
                            source = code_file.read()
                        tree = ast.parse(source, filename=full_path)
                        visitor = ForbiddenFunctionVisitor(full_path)
                        visitor.visit(tree)
                        all_violations.extend(visitor.violations)

        self.assertEqual(len(all_violations), 0, f"Found violations of forbidden functions:\n" + "\n".join(all_violations))


if __name__ == "__main__":
    unittest.main()
