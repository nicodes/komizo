import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('operator_tool',Path(__file__).resolve().parent/'assets/fleet_operator.py')
operator=importlib.util.module_from_spec(spec);spec.loader.exec_module(operator)
HEAD='a'*40
CONTRACT={'workflow_id':100,'workflow_path':'.github/workflows/ci.yml','app_id':15368,'event':'pull_request','jobs':['check'],'integration_job':'test'}
POLICY={'version':3,'repositories':{'owner/product':CONTRACT},'hosts':['box.example']}


class OperatorBoundary(unittest.TestCase):
    def test_delivery_is_issued_only_after_actual_merge_tree_matches(self):
        policy={**POLICY,'deployments':{'owner/product':{'host':'box.example','app':'product','repository_id':'123'}}}
        request={'operation':'merge','repository':'owner/product','pull_request':12,'head':HEAD}
        result=operator.execute(request,policy,self.backend)
        self.assertTrue(result['delivery_authorized'])
        deliveries=[call for call in self.calls if call[0]=='ssh']
        self.assertEqual(len(deliveries),1)
        import base64
        wire=deliveries[0][-1].split(' --authorization ')[1]
        authorization=json.loads(base64.b64decode(wire))
        self.assertEqual(authorization['revision'],self.pr['merge_commit_sha'])
        self.assertEqual(authorization['tree'],self.integration['tree'])
        self.assertEqual(authorization['integration_artifact_id'],55)
        self.setUp()
        original=self.backend
        def raced(args):
            result=original(args)
            if '/git/commits/' in args[-1] and self.pr['merged']:result['tree']['sha']='9'*40
            return result
        with self.assertRaises(ValueError):operator.execute(request,policy,raced)
        self.assertFalse(any(call[0]=='ssh' for call in self.calls))

    def test_standalone_entrypoint_refuses_invalid_json_without_import_failure(self):
        result = subprocess.run([sys.executable, str(Path(operator.__file__))],
                                input='not json', text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn('operator refused:', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_executor_ignores_poisoned_environment_and_cwd(self):
        program = 'import json,os;print(json.dumps({"cwd":os.getcwd(),"path":os.getenv("PATH"),"token":os.getenv("GH_TOKEN"),"ssh":os.getenv("GIT_SSH_COMMAND")}))'
        with patch.dict(os.environ, {'PATH':'/untrusted','GH_TOKEN':'editor-token','GIT_SSH_COMMAND':'untrusted'}), patch.dict(operator.EXECUTABLES, {'gh':'/usr/bin/python3'}):
            result=operator.command(['gh','-c',program])
        self.assertEqual(result, {'cwd':'/','path':'/usr/bin:/bin','token':None,'ssh':None})

    def test_executor_stops_oversized_and_stalled_commands(self):
        with patch.dict(operator.EXECUTABLES, {'gh':'/usr/bin/python3'}), patch.object(operator,'MAX_OUTPUT_BYTES',1024):
            with self.assertRaisesRegex(ValueError,'size bound'):
                operator.command(['gh','-c','import sys;sys.stdout.write("x"*4096);sys.stdout.flush()'])
        with patch.dict(operator.EXECUTABLES, {'gh':'/usr/bin/python3'}), patch.object(operator,'COMMAND_SECONDS',.1):
            with self.assertRaisesRegex(ValueError,'deadline'):
                operator.command(['gh','-c','import time;time.sleep(10)'])

    def setUp(self):
        self.pr={'state':'open','draft':False,'merged':False,'base':{'ref':'main'},'head':{'sha':HEAD,'repo':{'full_name':'owner/product'}},'merge_commit_sha':'b'*40}
        self.evidence={'headRefOid':HEAD,'statusCheckRollup':[{'__typename':'CheckRun','name':'check','status':'COMPLETED','conclusion':'SUCCESS','detailsUrl':'https://github.com/owner/product/actions/runs/42/job/101'}]}
        self.workflow={'id':42,'workflow_id':100,'path':'.github/workflows/ci.yml','event':'pull_request','head_sha':HEAD,'repository':{'full_name':'owner/product'},'head_repository':{'full_name':'owner/product'},'status':'completed','conclusion':'success','run_attempt':2,'check_suite_id':300}
        self.job={'id':101,'name':'check','run_attempt':2,'head_sha':HEAD,'status':'completed','conclusion':'success','check_run_url':'https://api.github.com/repos/owner/product/check-runs/201'}
        self.producer={'app':{'id':15368},'name':'check','head_sha':HEAD,'check_suite':{'id':300},'details_url':self.evidence['statusCheckRollup'][0]['detailsUrl'],'status':'completed','conclusion':'success'}
        self.integration={'version':1,'repository':'owner/product','run_id':42,'attempt':2,'job':'test','head':HEAD,'base':'c'*40,'commit':'f'*40,'tree':'d'*40,'inputs_sha256':'e'*64}
        self.base='c'*40
        self.base_reads=0
        self.calls=[]
        locks=tempfile.TemporaryDirectory()
        self.addCleanup(locks.cleanup)
        replacement=patch.object(operator,'LOCKS',Path(locks.name)/'locks')
        replacement.start();self.addCleanup(replacement.stop)
        # CI cannot create UID-0 files. Substitute only fixture ownership;
        # exercise real flock, mode, descriptor and serialization behavior.
        ownership=patch.object(operator,'lock_owner',lambda info:info.st_uid==os.geteuid())
        ownership.start();self.addCleanup(ownership.stop)
    def backend(self,args):
        self.calls.append(args)
        if args[0]=='gh' and args[1]=='api' and '/files?' in args[-1]:return [{'filename':'src/app.py'}]
        if '/git/ref/heads/main' in args[-1]:self.base_reads+=1;return {'object':{'sha':self.base}}
        if '/artifacts?' in args[-1]:return {'total_count':1,'artifacts':[{'id':55,'name':'fleet-integration-42-2','size_in_bytes':1024,'expired':False}]}
        if '/artifacts/55/zip' in args[-1]:return self.integration
        if '/git/commits/' in args[-1]:return {'sha':args[-1].split('/')[-1],'tree':{'sha':'d'*40},'parents':[{'sha':'c'*40},{'sha':HEAD}]}
        if '/attempts/' in args[-1]:return {'total_count':1,'jobs':[self.job]}
        if '/actions/runs/' in args[-1]:return self.workflow
        if '/check-runs/' in args[-1]:return self.producer
        if args[0]=='ssh':return {'apps':[{'name':'product','version':HEAD,'stopped':False,'secrets':{'token':'do-not-return'}}]}
        if args[:3]==['gh','pr','view']:return self.evidence
        if args[:3]==['gh','pr','merge']:self.pr['merged']=True;return None
        return self.pr
    def merge(self):
        return operator.execute({'operation':'merge','repository':'owner/product','pull_request':12,'head':HEAD},POLICY,self.backend)
    def test_exact_green_head_merges_with_head_guard(self):
        self.assertEqual(self.merge()['status'],'source_merged')
        self.assertTrue(any(c[-2:]==['--match-head-commit',HEAD] for c in self.calls))
    def test_changed_head_failed_pending_or_skipped_critical_checks_refuse_before_merge(self):
        for field,value in [('headRefOid','c'*40)]:
            self.setUp();self.evidence[field]=value
            with self.assertRaises(ValueError):self.merge()
            self.assertFalse(any(c[:3]==['gh','pr','merge'] for c in self.calls))
        for status,conclusion in [('IN_PROGRESS',''),('COMPLETED','FAILURE'),('COMPLETED','CANCELLED'),('COMPLETED','SKIPPED')]:
            self.setUp();self.evidence['statusCheckRollup'][0].update(status=status,conclusion=conclusion)
            with self.assertRaises(ValueError):self.merge()
            self.assertFalse(self.pr['merged'])
    def test_wrong_repo_draft_base_or_head_refuse(self):
        for change in ['fork','draft','base','head']:
            self.setUp()
            if change=='fork':self.pr['head']['repo']['full_name']='attacker/product'
            elif change=='draft':self.pr['draft']=True
            elif change=='base':self.pr['base']['ref']='other'
            else:self.pr['head']['sha']='c'*40
            with self.assertRaises(ValueError):self.merge()
            self.assertFalse(self.pr['merged'])
    def test_impostor_workflow_producer_attempt_and_source_refuse(self):
        for target, field, value in [('producer','app',{'id':999999}),
                                     ('workflow','workflow_id',999),
                                     ('workflow','path','.github/workflows/unapproved.yml'),
                                     ('workflow','event','workflow_dispatch'),
                                     ('workflow','head_sha','c'*40),
                                     ('workflow','head_repository',{'full_name':'other/product'}),
                                     ('job','run_attempt',1),('job','id',999),
                                     ('producer','check_suite',{'id':999})]:
            with self.subTest(target=target,field=field):
                self.setUp();getattr(self,target)[field]=value
                with self.assertRaises(ValueError):self.merge()
                self.assertFalse(self.pr['merged'])
    def test_duplicate_mandatory_label_refuses(self):
        self.evidence['statusCheckRollup'].append(dict(self.evidence['statusCheckRollup'][0]))
        with self.assertRaisesRegex(ValueError,'ambiguous'):self.merge()
        self.assertFalse(self.pr['merged'])


    def test_stale_base_receipt_and_changed_main_refuse_before_merge(self):
        self.base='9'*40
        with self.assertRaisesRegex(ValueError,'different integration or base'):self.merge()
        self.assertFalse(self.pr['merged'])
        self.setUp()
        original=self.backend
        def changing(args):
            if '/git/ref/heads/main' in args[-1] and self.base_reads:
                self.base='9'*40
            return original(args)
        with self.assertRaisesRegex(ValueError,'main advanced'):
            operator.execute({'operation':'merge','repository':'owner/product','pull_request':12,'head':HEAD},POLICY,changing)
        self.assertFalse(self.pr['merged'])

    def test_wrong_attempt_job_tree_or_git_parents_refuse(self):
        for field,value in [('attempt',1),('job','build'),('head','9'*40),('tree','9'*40)]:
            self.setUp();self.integration[field]=value
            with self.assertRaises(ValueError):self.merge()
            self.assertFalse(self.pr['merged'])
        self.setUp()
        original=self.backend
        def changed(args):
            result=original(args)
            if '/git/commits/' in args[-1]:result['parents'][0]['sha']='9'*40
            return result
        with self.assertRaises(ValueError):
            operator.execute({'operation':'merge','repository':'owner/product','pull_request':12,'head':HEAD},POLICY,changed)
        self.assertFalse(self.pr['merged'])

    def test_external_writer_during_merge_is_detected_before_source_authorization(self):
        original=self.backend
        def raced(args):
            result=original(args)
            if '/git/commits/' in args[-1] and self.pr['merged']:
                result['parents'][0]['sha']='9'*40
            return result
        with self.assertRaisesRegex(ValueError,'delivery authorization refused'):
            operator.execute({'operation':'merge','repository':'owner/product','pull_request':12,'head':HEAD},POLICY,raced)
        self.assertTrue(self.pr['merged']) # GitHub has no atomic expected-base guard.

    def test_supported_mergers_serialize_and_recheck_after_queue(self):
        import threading
        entered=threading.Event();leave=threading.Event();second=threading.Event()
        def first():
            with operator.repository_lock('owner/product'):
                entered.set();leave.wait(2)
        def queued():
            with operator.repository_lock('owner/product'):second.set()
        one=threading.Thread(target=first);two=threading.Thread(target=queued)
        one.start();self.assertTrue(entered.wait(1));two.start()
        self.assertFalse(second.wait(.1));leave.set();one.join(2);two.join(2)
        self.assertTrue(second.is_set())

    def test_host_report_is_fixed_argv_and_filters_credentials(self):
        report=operator.execute({'operation':'host_report','host':'box.example'},POLICY,self.backend)
        self.assertNotIn('do-not-return',json.dumps(report))
        self.assertEqual(self.calls[0][-1],'komizo-box report')
        for host in ['other.example','box.example;cat /etc/secret','-oProxyCommand=bad']:
            with self.assertRaises(ValueError):operator.execute({'operation':'host_report','host':host},POLICY,self.backend)
    def test_unknown_actions_extra_fields_and_unscoped_repos_refuse(self):
        for request in [{'operation':'shell','command':'anything'},{'operation':'host_report','host':'box.example','command':'anything'},{'operation':'delivery','repository':'other/product','revision':HEAD}]:
            with self.assertRaises(ValueError):operator.execute(request,POLICY,self.backend)
        self.assertEqual(self.calls,[])
    def test_delivery_does_not_accept_another_revision(self):
        observed=operator.execute({'operation':'delivery','repository':'owner/product','revision':HEAD},POLICY,lambda _: {'workflow_runs':[{'head_branch':'main','head_sha':'c'*40,'status':'completed','conclusion':'success'}]})
        self.assertEqual(observed['status'],'missing')
    def test_verification_changes_need_a_private_review(self):
        original = self.backend
        def changed(args):
            return [{'filename':'.github/workflows/ci.yml'}] if '/files?' in args[-1] else original(args)
        with self.assertRaises(ValueError):
            operator.execute({'operation':'merge','repository':'owner/product','pull_request':12,'head':HEAD},POLICY,changed)
        self.assertFalse(self.pr['merged'])

    def test_embedded_tests_fixtures_and_renamed_verification_require_review(self):
        for row in [{'filename':'internal/app/ssh_test.go'},
                    {'filename':'src/auth.spec.ts'},
                    {'filename':'api/test_auth.py'},
                    {'filename':'client/testdata/expected.json'},
                    {'filename':'ui/package.json'},
                    {'filename':'api/AGENTS.md'},
                    {'filename':'src/runtime.go','previous_filename':'src/runtime_test.go'}]:
            with self.subTest(row=row):
                self.setUp()
                original=self.backend
                def changed(args):
                    return [row] if '/files?' in args[-1] else original(args)
                with patch.object(operator,'private_json',side_effect=OSError()), self.assertRaisesRegex(ValueError,'review receipt'):
                    operator.execute({'operation':'merge','repository':'owner/product','pull_request':12,'head':HEAD},POLICY,changed)
                self.assertFalse(self.pr['merged'])

    def test_embedded_test_review_binds_exact_head_and_changed_paths(self):
        paths=['internal/app/ssh_test.go']
        body=json.dumps({'version':1,'repository':'owner/product','head':HEAD,
                         'reviewed_paths':paths}).encode()
        receipt={'version':1,'repository':'owner/product','head':HEAD,
                 'paths_sha256':hashlib.sha256(json.dumps(paths,separators=(',',':')).encode()).hexdigest(),
                 'ci_contract_reviewed':True,'evidence_sha256':hashlib.sha256(body).hexdigest()}
        original=self.backend
        def changed(args):
            return [{'filename':paths[0]}] if '/files?' in args[-1] else original(args)
        for altered in [dict(receipt,head='c'*40),dict(receipt,paths_sha256='e'*64)]:
            with patch.object(operator,'private_json',return_value=altered), self.assertRaises(ValueError):
                operator.execute({'operation':'merge','repository':'owner/product','pull_request':12,'head':HEAD},POLICY,changed)
            self.assertFalse(self.pr['merged'])
        with patch.object(operator,'private_json',return_value=receipt), patch.object(operator,'private_bytes',return_value=body):
            result=operator.execute({'operation':'merge','repository':'owner/product','pull_request':12,'head':HEAD},POLICY,changed)
        self.assertEqual(result['status'],'source_merged')

    def test_evidence_payload_missing_changed_or_rebound_refuses_before_merge(self):
        paths=['tools/fleet_operator.py']
        valid={'version':1,'repository':'owner/product','head':HEAD,'reviewed_paths':paths}
        digest=hashlib.sha256(json.dumps(paths,separators=(',',':')).encode()).hexdigest()
        for label, payload in [('missing',None),('mutated',dict(valid)),
                               ('head',dict(valid,head='c'*40)),
                               ('repository',dict(valid,repository='other/product')),
                               ('paths',dict(valid,reviewed_paths=['tools/other.py']))]:
            with self.subTest(label=label):
                self.setUp()
                body=json.dumps(payload).encode()
                receipt={'version':1,'repository':'owner/product','head':HEAD,
                         'paths_sha256':digest,'ci_contract_reviewed':True,
                         'evidence_sha256':hashlib.sha256(body).hexdigest()}
                original=self.backend
                def changed(args):
                    return [{'filename':paths[0]}] if '/files?' in args[-1] else original(args)
                with patch.object(operator,'private_json',return_value=receipt), patch.object(
                        operator,'private_bytes',side_effect=OSError() if payload is None else None,
                        return_value=body+b' ' if label=='mutated' else body), self.assertRaises(ValueError):
                    operator.execute({'operation':'merge','repository':'owner/product','pull_request':12,'head':HEAD},POLICY,changed)
                self.assertFalse(self.pr['merged'])

    def test_private_evidence_bytes_refuse_oversize_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'evidence';path.write_bytes(b'x'*(operator.MAX_BYTES+1));path.chmod(0o600)
            with self.assertRaises(ValueError):operator.private_bytes(path)
            link=Path(directory)/'linked';link.symlink_to(path)
            with self.assertRaises((ValueError,OSError)):operator.private_bytes(link)

    def test_policy_permissions_and_symlinks_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'policy';path.write_text(json.dumps(POLICY));path.chmod(0o644)
            with self.assertRaises(ValueError):operator.private_policy(path)
            path.chmod(0o600)
            if os.geteuid()==0:self.assertEqual(operator.private_policy(path),POLICY)
            else:
                with self.assertRaises(ValueError):operator.private_policy(path)
            link=Path(directory)/'linked';link.symlink_to(path)
            with self.assertRaises((ValueError,OSError)):operator.private_policy(link)


if __name__=='__main__':unittest.main()
