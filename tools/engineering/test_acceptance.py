import copy
import hashlib
import io
import tarfile
import tempfile
import json
import math
from pathlib import Path
import unittest

from onboarding_acceptance import validate_argv, observed_inspection
from performance_acceptance import evaluate
from release_acceptance import REQUIRED_STEPS, validate, validate_bundle


class AcceptanceGuards(unittest.TestCase):
    def setUp(self):
        self.budget=json.loads(Path(__file__).with_name('acceptance-budgets.json').read_bytes())
        self.metrics={'setup_seconds':30,'deployment_seconds':2,'idle_control_pss_bytes':48<<20,
                      'route_seconds':[.1]*5,'operator_seconds':[.2]*5,'load_hot_bytes':64<<20,
                      'load_cpu_usec':2_000_000,'oom_events_unchanged':True,'owned_load_removed':True,
                      'control_processes':[{'role':'rootd','pid':1,'pss_bytes':48<<20,'executable_sha256':'c'*64}],
                      'control_services_running':{'rootd':True,'serve':False,'agent':False}}

    def test_rejects_vacuous_nonfinite_regressed_or_unloaded_measurements(self):
        self.assertTrue(evaluate(self.metrics,self.budget))
        for field,value in [('route_seconds',[]),('route_seconds',[math.nan]*5),('operator_seconds',[6]*5),
                            ('idle_control_pss_bytes',129<<20),('setup_seconds',361),('deployment_seconds',121),
                            ('load_hot_bytes',0),('load_cpu_usec',0),('oom_events_unchanged',False),('owned_load_removed',False)]:
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                evaluate({**self.metrics,field:value},self.budget)

    def test_release_promotion_refuses_wrong_source_candidate_missing_tests_and_cleanup(self):
        native={'version':1,'release':'v0.0.123','source':'a'*40,'candidate_cli':None,'cli_sha256':'b'*64,'host_sha256':'c'*64,'runner_sha256':'d'*64,
                'steps':[{'step':name,'accepted':True} for name in REQUIRED_STEPS],
                'private_cgroup_namespace':True,'host_global_kernel_controls_masked':True,'host_mounts':False,'host_docker_socket':False,
                'provider_calls':False,'real_data_accessed':False,'performance_accepted':True,'onboarding_mode':'deterministic_public_cli'}
        cleanup={'owned_container_removed':True,'shared_images_removed':False}
        performance={'accepted':True,'budget':self.budget,'metrics':self.metrics}
        onboarding={'accepted':True,'commands':4,'public_readme_sha256':'f'*64,'mode':'deterministic_public_cli','human_interventions':0,'provider_credentials_in_task':False,'source_checkout_in_task':False}
        args=[native,cleanup,performance,onboarding,'v0.0.123','a'*40,self.budget]
        self.assertTrue(validate(*args))
        for index,field,value in [(0,'source','e'*40),(0,'candidate_cli',{'authenticated':False}),(0,'steps',[]),
                                  (0,'host_mounts',True),(1,'owned_container_removed',False),(1,'shared_images_removed',True),
                                  (2,'accepted',False),(3,'human_interventions',1),(3,'source_checkout_in_task',True)]:
            bad=copy.deepcopy(args);bad[index][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):validate(*bad)

    def test_publication_refuses_swapped_bytes_even_with_replaced_checksums(self):
        engine=Path(__file__).parent
        source='a'*40;release='v0.0.123';binary=b'synthetic archive fixture, never executed'
        native={'version':1,'release':release,'source':source,'candidate_cli':None,'cli_sha256':hashlib.sha256(binary).hexdigest(),'host_sha256':'c'*64,
                'runner_sha256':hashlib.sha256((engine/'cold-lifecycle-acceptance.py').read_bytes()).hexdigest(),
                'steps':[{'step':name,'accepted':True} for name in REQUIRED_STEPS],
                'private_cgroup_namespace':True,'host_global_kernel_controls_masked':True,'host_mounts':False,'host_docker_socket':False,
                'provider_calls':False,'real_data_accessed':False,'performance_accepted':True,'onboarding_mode':'deterministic_public_cli'}
        performance={'accepted':True,'budget':self.budget,'metrics':self.metrics,'budget_sha256':hashlib.sha256((engine/'acceptance-budgets.json').read_bytes()).hexdigest()}
        onboarding={'accepted':True,'commands':4,'public_readme_sha256':hashlib.sha256((engine.resolve().parents[1]/'README.md').read_bytes()).hexdigest(),
                    'mode':'deterministic_public_cli','human_interventions':0,'provider_credentials_in_task':False,'source_checkout_in_task':False}
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);bundle=root/'evidence';archives=root/'archives';bundle.mkdir();archives.mkdir()
            def archive(path,payload):
                with tarfile.open(path,'w:gz') as tar:
                    for name,body in [('komizo',payload),('README.md',b'public usage'),('LICENSE',b'license')]:
                        entry=tarfile.TarInfo(name);entry.size=len(body);tar.addfile(entry,io.BytesIO(body))
            names=[f'komizo_{os}_{arch}.tar.gz' for os in ('Darwin','Linux') for arch in ('arm64','x86_64')]
            for name in names:archive(archives/name,binary)
            def checksums():
                (archives/'checksums.txt').write_text(''.join(hashlib.sha256((archives/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in names))
            checksums()
            (bundle/'komizo-performance.json').write_text(json.dumps(performance))
            summary={'accepted':True,'release':release,'source':source,'native':native,'cleanup':{'owned_container_removed':True,'shared_images_removed':False},
                     'onboarding':onboarding,'performance_sha256':hashlib.sha256((bundle/'komizo-performance.json').read_bytes()).hexdigest()}
            (bundle/'komizo-acceptance.json').write_text(json.dumps(summary))
            self.assertTrue(validate_bundle(bundle,release,source,archives))
            archive(archives/'komizo_Linux_x86_64.tar.gz',b'different binary');checksums()
            with self.assertRaisesRegex(ValueError,'executable differs'):validate_bundle(bundle,release,source,archives)

    def test_help_does_not_count_as_inspecting_the_operation(self):
        facts={'manifest':'a'*64}
        help_entry={'argv':['komizo','--json','platform','inspect','--help'],'response':{'ok':True,'data':{'text':'help'}}}
        self.assertFalse(observed_inspection([help_entry],facts))
        actual={'argv':['komizo','--json','platform','inspect'],'response':{'ok':True,'data':{'manifest':'a'*64,'phase':'installing'}}}
        self.assertTrue(observed_inspection([actual],facts))
        self.assertFalse(observed_inspection([actual],{'manifest':'b'*64}))

    def test_agent_cannot_escape_owned_target_or_choose_another_local_file(self):
        facts={'host':'192.0.2.1','definition':'/owned/app.json','key':'/owned/key','revision':'1'*40,'stage':'/var/lib/komizo/upgrades/owned','manifest':'2'*64}
        valid=['komizo','--json','setup','--host',facts['host'],'--definition',facts['definition'],'--key',facts['key']]
        self.assertEqual(validate_argv(valid,facts),'setup')
        bad=[['sh','-c','true'],['komizo','--json','remove','--host',facts['host']],valid[:4]+['another-host']+valid[5:],
             valid[:-1]+['/root/.ssh/id_ed25519'],valid[:5],valid+['--host',facts['host']],
             ['komizo','--json','platform','recover','--host',facts['host'],'--stage','/arbitrary/path','--expected-manifest','2'*64]]
        for argv in bad:
            with self.subTest(argv=argv),self.assertRaises(ValueError):validate_argv(argv,facts)


if __name__=='__main__':unittest.main()
