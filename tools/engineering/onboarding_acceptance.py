"""Public-instructions-only planning loop; the grader executes bounded CLI argv.

An adapter reads a JSON task on stdin and returns {"argv":["komizo",...]}.
It gets no SSH key, token, source checkout or execution access. Only the grader
can execute the installed CLI, against this fixture's exact host and paths.
"""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import time


def validate_argv(argv, facts):
    if not isinstance(argv,list) or not 3 <= len(argv) <= 40 or any(not isinstance(v,str) or len(v)>1024 for v in argv):
        raise ValueError('adapter must return bounded argv')
    if argv[:2] != ['komizo','--json']:
        raise ValueError('adapter must use the public machine interface')
    command = argv[2]
    if command not in ('capabilities','help','doctor','setup','deploy','operation','platform'):
        raise ValueError('onboarding command is outside its authority')
    if command in ('capabilities','help'):
        if len(argv)!=3: raise ValueError('discovery accepts no fixture arguments')
        return command
    rest=argv[3:]
    if rest in (['--help'],['-h']):return command
    if command in ('operation','platform'):
        if not rest or rest[0] not in ('inspect','recover'):
            raise ValueError('only explicit inspection/recovery is permitted')
        command+=' '+rest[0];rest=rest[1:]
    if rest in (['--help'],['-h']):return command
    values={'--host':{facts['host'],'root@'+facts['host']},'--app':{'fixturelocal'},'--port':{'22'}}
    for name,field in (('--definition','definition'),('--key','key'),('--version','revision'),('--stage','stage'),('--expected-manifest','manifest')):
        if field in facts:values[name]={facts[field]}
    pairs=[];index=0
    while index<len(rest):
        token=rest[index]
        if not token.startswith('-') or token.startswith('---'):raise ValueError('flags required')
        if '=' in token:
            name,value=token.split('=',1);index+=1
        else:
            if index+1>=len(rest):raise ValueError('flag value required')
            name,value=token,rest[index+1];index+=2
        pairs.append(('--'+name.lstrip('-'),value))
    if len({k for k,_ in pairs})!=len(pairs):raise ValueError('use unambiguous flag/value pairs')
    supplied=dict(pairs)
    if '--host' not in supplied or any(k not in values or v not in values[k] for k,v in supplied.items()):
        raise ValueError('onboarding target or input differs from its owned fixture')
    if command=='setup' and 'definition' in facts and (supplied.get('--definition')!=facts['definition'] or supplied.get('--key')!=facts['key']):
        raise ValueError('app setup must use its supplied definition and owned key file')
    if command=='deploy' and (supplied.get('--app')!='fixturelocal' or supplied.get('--version')!=facts.get('revision')):
        raise ValueError('deployment must use the exact authorized app and revision')
    if command.startswith('platform') and ('stage' not in facts or supplied.get('--stage')!=facts['stage'] or supplied.get('--expected-manifest')!=facts['manifest']):
        raise ValueError('recovery must bind the exact reviewed stage')
    if command=='operation recover':
        raise ValueError('this fixture authorizes only platform configuration recovery')
    return command


def observed_inspection(history,facts):
    return any(e.get('argv',[])[2:4]==['platform','inspect'] and e.get('response',{}).get('ok') and
               e['response'].get('data',{}).get('manifest')==facts.get('manifest') and
               e['response'].get('data',{}).get('phase') in ('prepared','installing','recovering') for e in history)


class Driver:
    def __init__(self, adapter, output, readme, cli, env, host):
        self.adapter,self.output,self.readme,self.cli,self.env,self.host=adapter,output,readme,cli,env,host
        self.trace=[];self.rejections=[];self.observations=[];self.started=time.monotonic();self.last_seconds=0

    def command(self, goal, facts, fallback, expected, predicate=lambda data:True, timeout=360):
        facts={'host':self.host,'ssh_access_configured':True,'ssh_port':22,'ssh_host_key_pinned':True,'trust_changes_authorized':False,**facts}
        if self.adapter is None:
            start=time.monotonic();result=subprocess.run(fallback,env=self.env,capture_output=True,timeout=timeout,check=True);self.last_seconds=time.monotonic()-start
            self.trace.append({'goal':goal,'argv':['komizo',*fallback[1:]],'seconds':self.last_seconds,'returncode':result.returncode,'response':json.loads(result.stdout)})
            self.save(False)
            return result.stdout
        history=self.observations
        for attempt in range(12):
            if time.monotonic()-self.started>1800:raise ValueError('onboarding deadline exceeded')
            task={'version':1,'goal':goal,'public_readme':self.readme,'operator_inputs':facts,'observations':history,
                  'instruction':'Return JSON with argv for one next public komizo command. No shell, source inspection, external tools or human assistance. Discover flags with CLI help. The operator authorizes only this disposable host and supplied inputs.'}
            # Model/provider credentials stay with the adapter. The task never
            # carries the native observer environment or its GitHub/SSH secrets.
            adapter_env={k:v for k,v in os.environ.items() if k in ('PATH','HOME','LANG','HTTP_PROXY','HTTPS_PROXY','NO_PROXY')}
            answer=subprocess.run([str(self.adapter)],input=json.dumps(task).encode(),env=adapter_env,capture_output=True,timeout=180,check=True)
            request=json.loads(answer.stdout);argv=request.get('argv')
            try:
                command=validate_argv(argv,facts)
                if command=='platform recover' and not observed_inspection(history,facts):
                    raise ValueError('inspect this exact operation before selecting recovery')
            except ValueError as error:
                entry={'goal':goal,'request':request,'refusal':str(error)};history.append(entry);self.rejections.append(entry);self.save(False);continue
            start=time.monotonic()
            result=subprocess.run([str(self.cli),*argv[1:]],env=self.env,capture_output=True,timeout=timeout)
            if len(result.stdout)>4<<20:raise ValueError('onboarding response exceeded its bound')
            response=json.loads(result.stdout)
            self.last_seconds=time.monotonic()-start
            entry={'goal':goal,'argv':argv,'seconds':time.monotonic()-start,'returncode':result.returncode,'response':response}
            history.append(entry);self.trace.append(entry)
            self.save(False)
            if command==expected and result.returncode==0 and response.get('ok') and predicate(response['data']):
                return result.stdout
        raise ValueError('unfamiliar agent did not complete the task within twelve commands')

    def save(self, accepted):
        result={'version':1,'mode':'unfamiliar_agent' if self.adapter else 'deterministic_public_cli',
                'accepted':accepted,'public_readme_sha256':hashlib.sha256(self.readme.encode()).hexdigest(),'rejected_proposals':len(self.rejections),'rejections':self.rejections,'human_interventions':0,'commands':len(self.trace),'seconds':time.monotonic()-self.started,
                'inputs':['public README','explicit disposable operator inputs','public CLI observations'],
                'provider_credentials_in_task':False,'source_checkout_in_task':False,'trace':self.trace}
        (self.output/'onboarding.json').write_text(json.dumps(result,indent=2)+'\n')
