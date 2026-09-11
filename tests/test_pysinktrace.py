import tempfile
import unittest
from pathlib import Path

from pysinktrace import scan


class PySinkTraceTests(unittest.TestCase):
    def scan_code(self, code):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.py"
            path.write_text(code, encoding="utf-8")
            return scan(path)

    def test_tracks_assignment_into_command_sink(self):
        findings = self.scan_code('''
def route():
    name = request.args.get("name")
    command = "echo " + name
    os.system(command)
''')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, (3, 3, 4, 5))
        self.assertEqual(findings[0].severity, "critical")

    def test_recognizes_integer_conversion(self):
        findings = self.scan_code('''
def route():
    count = int(request.args.get("count"))
    os.system("echo " + str(count))
''')
        self.assertEqual(findings, [])

    def test_emits_sql_rule(self):
        findings = self.scan_code('''
def route():
    key = request.form.get("key")
    cursor.execute("SELECT * FROM t WHERE k=" + key)
''')
        self.assertEqual(findings[0].rule_id, "PST003")

    def test_tracks_source_wrapper(self):
        findings = self.scan_code('''
def user_value():
    return request.args.get("value")

def route():
    value = user_value()
    eval(value)
''')
        self.assertEqual(findings[0].rule_id, "PST002")
        self.assertTrue(findings[0].source.startswith("wrapper:user_value"))

    def test_tracks_sink_wrapper(self):
        findings = self.scan_code('''
def execute(command):
    os.system(command)

def route():
    value = request.form.get("value")
    execute(value)
''')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].sink, "os.system")
        self.assertIn(6, findings[0].path)


if __name__ == "__main__":
    unittest.main()
