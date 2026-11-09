import importlib.util
import json
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('native_root_tests', Path(__file__).with_name('native-root-tests.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class RootFixtureAdmission(unittest.TestCase):
    def output(self):
        return [dict(reason='compiler-artifact', target={'name': name}, executable='/owned/' + name)
                for name in reversed(native.TARGETS)]

    def test_every_native_suite_is_required_before_any_privileged_execution(self):
        rows = self.output()
        self.assertEqual(native.executables('\n'.join(map(json.dumps, rows))),
                         ['/owned/' + name for name in native.TARGETS])
        for changed in (rows[1:], rows + [rows[0]], rows[:-1] + [dict(rows[-1], executable=None)]):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                native.executables('\n'.join(map(json.dumps, changed)))

    def test_unrelated_build_program_cannot_replace_an_omitted_native_suite(self):
        rows = self.output()[1:]
        rows.append(dict(reason='compiler-artifact', target={'name': 'unrelated'}, executable='/foreign/program'))
        with self.assertRaises(RuntimeError):
            native.executables('\n'.join(map(json.dumps, rows)))


if __name__ == '__main__':
    unittest.main()
