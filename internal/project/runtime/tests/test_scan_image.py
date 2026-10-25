import copy
import tempfile
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('scan_image', Path(__file__).resolve().parents[1]/'helpers/scan-image.py')
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class ImageVerdict(unittest.TestCase):
    def report(self, finding=None):
        rows = [{'config': {'protocol_version': 'v1.0.0', 'scanner_name': 'govulncheck',
                 'scanner_version': 'v1.7.0', 'scan_level': 'symbol', 'scan_mode': 'binary'}},
                {'SBOM': {'modules': [{'path': 'example.org/app', 'version': 'v1.0.0'}]}}]
        if finding is not None:
            rows.append({'finding': finding})
        return rows

    def judge(self, rows):
        return scanner.judge_report('\n'.join(json.dumps(row) for row in rows))

    def finding(self):
        return {'osv': 'GO-2026-6355', 'fixed_version': 'v0.56.0', 'trace': [
            {'module': 'golang.org/x/crypto', 'version': 'v0.55.0',
             'package': 'golang.org/x/crypto/ssh', 'function': 'Dial'}]}

    def test_binary_symbol_blocks_without_source_position(self):
        self.assertEqual(self.judge(self.report(self.finding()))['reached'], ['GO-2026-6355'])
        finding = self.finding()
        del finding['fixed_version']
        self.assertEqual(self.judge(self.report(finding))['reached'], ['GO-2026-6355'])

    def test_module_and_package_mentions_are_reported_not_called_symbols(self):
        for frame in [{'module': 'golang.org/x/crypto', 'version': 'v0.56.0'},
                      {'module': 'golang.org/x/crypto', 'package': 'golang.org/x/crypto/openpgp'}]:
            verdict = self.judge(self.report({'osv': 'GO-2026-5932', 'trace': [frame]}))
            self.assertEqual(verdict['reached'], [])
            self.assertEqual(verdict['mentioned'], ['GO-2026-5932'])

    def test_missing_renamed_or_wrongly_typed_protocol_fails_closed(self):
        rows = self.report(self.finding())
        invalid = [[], rows[1:], rows[:1], rows + [rows[0]], rows + [{'results': {}}]]
        for key, value in [('fixed_version', False), ('trace', []), ('trace', {}), ('osv', 3)]:
            changed = copy.deepcopy(rows)
            changed[-1]['finding'][key] = value
            invalid.append(changed)
        for key in ['function', 'package', 'module']:
            changed = copy.deepcopy(rows)
            changed[-1]['finding']['trace'][0][key] = False
            invalid.append(changed)
        changed = copy.deepcopy(rows)
        changed[-1]['finding']['trace'][0]['symbol'] = changed[-1]['finding']['trace'][0].pop('function')
        invalid.append(changed)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.judge(value)
        with self.assertRaises(ValueError):
            scanner.judge_report('{"config":')


if __name__ == '__main__':
    unittest.main()


class UpstreamExemption(unittest.TestCase):
    """--upstream accepts a binary we did not build. It must match exactly.

    The exemption is the only way a reached advisory does not fail the build,
    so the cost of getting the comparison wrong runs both ways: too loose and
    a binary we DID build stops being checked; too strict and the exemption
    silently does nothing while the command line reads as though it works.
    """

    def test_a_tar_member_matches_the_absolute_path_an_operator_writes(self):
        # tar gives "usr/bin/caddy"; the operator writes the path as it is
        # inside the image. Both spellings, and the "./" form, are one path.
        for member in ('usr/bin/caddy', './usr/bin/caddy', '/usr/bin/caddy'):
            self.assertTrue(scanner.is_upstream(member, ['/usr/bin/caddy']), member)
            self.assertTrue(scanner.is_upstream(member, ['usr/bin/caddy']), member)

    def test_nothing_else_is_exempt(self):
        for member in ('usr/bin/sampleservice-api', 'usr/local/bin/caddy', 'usr/bin/caddy2',
                       'opt/caddy', 'usr/bin/caddy/inner'):
            self.assertFalse(scanner.is_upstream(member, ['/usr/bin/caddy']), member)

    def test_no_declaration_exempts_nothing(self):
        self.assertFalse(scanner.is_upstream('usr/bin/caddy', []))

    def test_several_paths_may_be_declared(self):
        declared = ['/usr/bin/caddy', '/usr/sbin/other']
        self.assertTrue(scanner.is_upstream('usr/sbin/other', declared))
        self.assertFalse(scanner.is_upstream('usr/sbin/others', declared))



class ForbiddenLiterals(unittest.TestCase):
    """The artifact question source inspection cannot answer.

    sampleapp is the case that proves it is a separate question: its
    development identity is compiled out behind a build tag, every test
    passes in both builds, and the string is still in the binary through a
    seeding fixture whose code can never run. Reachable and present are not
    the same property.
    """

    def binary(self, directory, contents):
        path = Path(directory) / 'executable'
        path.write_bytes(contents)
        return path

    def test_a_present_literal_is_found(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = self.binary(directory, b'\x7fELF\x00\x00dev_local_user\x00padding')
            self.assertEqual(scanner.forbidden_strings(binary, ['dev_local_user']),
                             ['dev_local_user'])

    def test_an_absent_literal_is_not_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = self.binary(directory, b'\x7fELF\x00ordinary content\x00')
            self.assertEqual(scanner.forbidden_strings(binary, ['dev_local_user']), [])

    def test_every_present_literal_is_named_at_once(self):
        """One run should report the whole problem, not the first of it."""
        with tempfile.TemporaryDirectory() as directory:
            binary = self.binary(directory, b'\x7fELFdev_local_user and clerk.local.invalid here')
            self.assertEqual(
                scanner.forbidden_strings(binary, ['clerk.local.invalid', 'dev_local_user', 'absent']),
                ['clerk.local.invalid', 'dev_local_user'])

    def test_it_reads_bytes_rather_than_decoding(self):
        """A Go binary is not text; a literal is present or it is not."""
        with tempfile.TemporaryDirectory() as directory:
            binary = self.binary(directory, b'\x7fELF\xff\xfe\x80dev_local_user\x00\xc3\x28')
            self.assertEqual(scanner.forbidden_strings(binary, ['dev_local_user']),
                             ['dev_local_user'])

    def test_nothing_forbidden_means_nothing_to_report(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = self.binary(directory, b'\x7fELFdev_local_user')
            self.assertEqual(scanner.forbidden_strings(binary, []), [])
