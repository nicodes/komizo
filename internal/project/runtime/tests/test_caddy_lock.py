from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE = 'google.golang.org/grpc'
# Authenticated by go mod download (sum.golang.org), not copied from a scan.
REPAIR_SUMS = {
    'v1.83.2': 'h1:EManeRomTObA0BU7I8vXgg/78uE5MJ9M8B39EX2WscU=',
    'v1.83.2/go.mod': 'h1:YPI1hK3kDked6iHvgX3tR0y+nX/qpMFKhPgFsokw1S8=',
}


class CaddyLock(unittest.TestCase):
    def setUp(self):
        self.mod = (ROOT/'helpers/caddy.go.mod').read_text()
        self.sums = (ROOT/'helpers/caddy.go.sum').read_text()

    def assert_secure_lock(self, mod, sums):
        versions = re.findall(r'^\s*google\.golang\.org/grpc\s+(\S+)', mod, re.M)
        self.assertEqual(len(versions), 1)
        version = versions[0]
        release = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)', version)
        self.assertIsNotNone(release, 'require an exact stable gRPC release')
        # On this lock's 1.83 line, .2 fixes GO-2026-6443; .1 already fixes
        # GO-2026-6348. Permit future secure upgrades, never a downgrade.
        self.assertGreaterEqual(tuple(map(int, release.groups())), (1, 83, 2))
        for suffix in ('', '/go.mod'):
            key = version + suffix
            entries = [line.split() for line in sums.splitlines()
                       if line.startswith(f'{MODULE} {key} ')]
            self.assertEqual(len(entries), 1, f'missing or duplicate sum: {key}')
            self.assertEqual(len(entries[0]), 3)
            self.assertRegex(entries[0][2], r'^h1:[A-Za-z0-9+/]{43}=$')
            if key in REPAIR_SUMS:
                self.assertEqual(entries[0][2], REPAIR_SUMS[key])

    def test_locked_grpc_has_both_security_fixes_and_complete_sums(self):
        self.assert_secure_lock(self.mod, self.sums)

    def test_vulnerable_or_unreleased_locks_are_rejected(self):
        for version in ('v1.82.1', 'v1.83.1', 'v1.83.2-dev'):
            changed = re.sub(r'(google\.golang\.org/grpc\s+)\S+',
                             lambda match: match[1] + version, self.mod)
            with self.subTest(version=version), self.assertRaises(AssertionError):
                self.assert_secure_lock(changed, self.sums)

    # GO-2026-6508: the OpenTelemetry gRPC log exporter ignores the TLS
    # certificates given in the environment, bypassing mTLS and certificate
    # pinning. Fixed in v0.21.0, and reachable in the built binary -- it broke
    # every product vendoring this lock on the day it was published.
    #
    # THE WHOLE FAMILY, not just the exporter that was named. otlploggrpc,
    # otlploghttp and stdoutlog release together against one otel/log and one
    # sdk/log, and the first repair here moved the exporter alone: it left two
    # of them a release behind their own sdk, which is a version skew nobody
    # chose and the next advisory would have found again. A floor per module,
    # so an upgrade is always allowed and a downgrade never is.
    OTEL_LOG_FLOOR = {
        'go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc': (0, 21, 0),
        'go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp': (0, 21, 0),
        'go.opentelemetry.io/otel/exporters/stdout/stdoutlog': (0, 21, 0),
        'go.opentelemetry.io/otel/log': (0, 21, 0),
        'go.opentelemetry.io/otel/sdk/log': (0, 21, 0),
    }

    def assert_otel_log_floor(self, mod):
        for module, floor in self.OTEL_LOG_FLOOR.items():
            versions = re.findall(rf'^\s*{re.escape(module)}\s+(\S+)', mod, re.M)
            self.assertEqual(len(versions), 1, f'{module}: expected exactly one pin')
            release = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)', versions[0])
            self.assertIsNotNone(release, f'{module}: require an exact stable release')
            self.assertGreaterEqual(tuple(map(int, release.groups())), floor,
                                    f'{module}: GO-2026-6508 needs at least v0.21.0')

    def test_locked_otel_log_exporters_are_past_the_tls_bypass(self):
        self.assert_otel_log_floor(self.mod)

    def test_an_otel_log_module_left_behind_is_rejected(self):
        for module in self.OTEL_LOG_FLOOR:
            changed = re.sub(rf'(^\s*{re.escape(module)}\s+)\S+',
                             lambda match: match[1] + 'v0.19.0', self.mod, flags=re.M)
            with self.subTest(module=module), self.assertRaises(AssertionError):
                self.assert_otel_log_floor(changed)

    def test_missing_or_inconsistent_repair_sums_are_rejected(self):
        # Use the repair release fixture even after the live lock advances.
        mod = f'require (\n\t{MODULE} v1.83.2\n)\n'
        sums = ''.join(f'{MODULE} {key} {value}\n' for key, value in REPAIR_SUMS.items())
        self.assert_secure_lock(mod, sums)
        for line in sums.splitlines(keepends=True):
            for changed in (sums.replace(line, ''), sums + line,
                            sums.replace(line, line.replace('h1:', 'h1:A', 1)),
                            sums.replace(line, re.sub(r'h1:.', 'h1:A', line))):
                with self.subTest(line=line, changed=changed), self.assertRaises(AssertionError):
                    self.assert_secure_lock(mod, changed)


if __name__ == '__main__':
    unittest.main()
