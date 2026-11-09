"""Export finite nonsecret source-candidate observations without a release claim."""
import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from release_acceptance import read, read_budget, sha, REQUIRED_STEPS, validate_measurements

CANDIDATE_STEPS=set(REQUIRED_STEPS)
BOUNDED_STEPS={'real_reboot','bounded_full_postgresql_offline_reboot','fixed_budget_performance',
    'real_postgresql_api_dag','shared_dns_control_budget','owner_postgresql_encrypted_restore','recovery_private_key_outside_capture_host'}


def export(observations,output,source):
    if not re.fullmatch('[a-f0-9]{40}',source) or output.exists() or output.is_symlink():raise ValueError('exact source and fresh output required')
    result=read(observations/'candidate-deployment.json');cleanup=read(observations/'cleanup.json')
    if (result.get('source')!=source or result.get('accepted') is not True or result.get('signed_release_acceptance') is not False
            or result.get('candidate_cli',{}).get('authenticated') is not False or result.get('github_credentials_present') is not False
            or type(cleanup.get('version')) is not int or cleanup!={'version':1,'owned_guest_removed':True,'private_storage_removed':True,'shared_images_removed':False}):
        raise ValueError('candidate identity, isolation, scope or owned cleanup differs')
    profiles=result.get('profiles',{})
    if not isinstance(profiles,dict) or set(profiles)!={'functional','bounded'}:raise ValueError('both source candidate profiles are required')
    for name,required in [('functional',CANDIDATE_STEPS),('bounded',BOUNDED_STEPS)]:
        profile=profiles[name]
        if (profile.get('ok') is not True or profile.get('profile')!=name or profile.get('source')!={'revision':source,'binary_sha256':result.get('host_sha256')}
                or any(profile.get('checks',{}).get(name)!='passed' for name in required)):
            raise ValueError('source candidate native effects, small-host fit or exact running executable differ')
    performance=read(observations/'performance.json');onboarding=read(observations/'onboarding.json')
    root=Path(__file__).parent;budget=read_budget(root/'acceptance-budgets.toml')
    validate_measurements(performance,onboarding,{'host_sha256':result['host_sha256'],'proxy_sha256':result['proxy_sha256'],
        'cli_sha256':result['candidate_cli']['sha256']},budget)
    if performance['budget_sha256']!=sha(root/'acceptance-budgets.toml') or onboarding['public_readme_sha256']!=sha(root.parents[1]/'README.md'):
        raise ValueError('source candidate budget or public owner instructions changed')
    for name in ('host_sha256','proxy_sha256'):
        if not re.fullmatch('[a-f0-9]{64}',result.get(name,'')):raise ValueError('candidate native binary identity missing')
    if not re.fullmatch('[a-f0-9]{64}',result['candidate_cli'].get('sha256','')):raise ValueError('candidate owner identity missing')
    output.mkdir(mode=0o700)
    # Do not copy arbitrary transcripts, paths or raw fixture reports.
    closed={key:result[key] for key in ('source','accepted','signed_release_acceptance','github_credentials_present','host_sha256','proxy_sha256')}
    closed['candidate_cli']={key:result['candidate_cli'][key] for key in ('authenticated','sha256')}
    closed['profiles']={}
    for name,required in [('functional',CANDIDATE_STEPS),('bounded',BOUNDED_STEPS)]:
        closed['profiles'][name]={key:profiles[name][key] for key in ('ok','profile','source')}
        closed['profiles'][name]['checks']={check:'passed' for check in sorted(required)}
    owner={key:onboarding[key] for key in ('accepted','mode','commands','seconds','human_interventions','provider_credentials_in_task','source_checkout_in_task','public_readme_sha256','cli_sha256')}
    for name,row in [('candidate-deployment.json',closed),('candidate-performance.json',performance),('candidate-onboarding.json',owner),('cleanup.json',cleanup)]:
        (output/name).write_text(json.dumps(row,sort_keys=True)+'\n')



if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--observations',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--source',required=True)
    args=parser.parse_args();export(args.observations,args.output,args.source)
