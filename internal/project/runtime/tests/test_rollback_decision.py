import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('rollback', Path(__file__).resolve().parents[1]/'helpers/rollback-decision.py')
rollback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rollback)


class RollbackProof(unittest.TestCase):
    def test_absent_failed_or_other_revision_proof_never_authorizes(self):
        current, previous = 'a'*40, 'b'*40
        old = {'version': 1, 'source_revision': previous, 'schema': {'minimum': 1, 'maximum': 2, 'write': 1},
               'data_revision': 'records-v1', 'credential_revision': 'runtime-grants-v1',
               'migrations': [{'identity': '001.sql', 'sha256': 'd'*64}], 'recovery_action': 'forward_only'}
        new = {**old, 'source_revision': current, 'schema': {'minimum': 1, 'maximum': 2, 'write': 2}, 'recovery_action': 'image_rollback'}
        declaration = {'automatic_image_rollback': True, 'stateful_contract': new, 'previous_stateful_contract': old}
        proof = {'version': 2, 'run_id': '123', 'current_revision': current, 'previous_revision': previous,
                 'current_contract_sha256': rollback.stateful_release.identity(new),
                 'previous_contract_sha256': rollback.stateful_release.identity(old),
                 'observed_schema': 2, 'data_revision': 'records-v1', 'credential_revision': 'runtime-grants-v1',
                 'status': 'passed', 'snapshot_sha256': 'c'*64,
                 'operations': {name: 'passed' for name in rollback.OPERATIONS}}
        def decide(d, e):
            return rollback.decide(d, e, current, previous, '123')['allowed']
        self.assertTrue(decide(declaration, proof))
        self.assertFalse(decide({}, proof))
        self.assertFalse(decide({'automatic_image_rollback': False}, proof))
        self.assertFalse(decide(declaration, None))
        for key, value in [('current_revision', 'd'*40), ('previous_revision', 'd'*40),
                           ('run_id', '456'), ('status', 'failed'), ('snapshot_sha256', '')]:
            changed = {**proof, key: value}
            self.assertFalse(decide(declaration, changed))
        for operation in rollback.OPERATIONS:
            changed = copy.deepcopy(proof)
            del changed['operations'][operation]
            self.assertFalse(decide(declaration, changed))


if __name__ == '__main__':
    unittest.main()
