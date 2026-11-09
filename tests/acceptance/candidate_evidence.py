"""Export finite nonsecret source-candidate observations without a release claim."""
import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from release_acceptance import read

CANDIDATE_STEPS={'supported_host','root_peer','static_archive','service_job_dag','owner_empty_data_enrollment',
    'nonempty_data_initialization_refused','unenrolled_production_refused','mutation_replay','controller_death',
    'shared_dns_control_budget','failed_job_no_replay','interrupted_job_no_replay','real_postgresql_api_dag',
    'owner_postgresql_encrypted_restore','recovery_private_key_outside_capture_host','real_reboot'}


def export(observations,output,source):
    if not re.fullmatch('[a-f0-9]{40}',source) or output.exists() or output.is_symlink():raise ValueError('exact source and fresh output required')
    result=read(observations/'candidate-deployment.json');cleanup=read(observations/'cleanup.json')
    if (result.get('source')!=source or result.get('accepted') is not True or result.get('signed_release_acceptance') is not False
            or result.get('candidate_cli',{}).get('authenticated') is not False or result.get('github_credentials_present') is not False
            or type(cleanup.get('version')) is not int or cleanup!={'version':1,'owned_guest_removed':True,'private_storage_removed':True,'shared_images_removed':False}):
        raise ValueError('candidate identity, isolation, scope or owned cleanup differs')
    profile=result.get('profile',{})
    if (profile.get('ok') is not True or profile.get('profile')!='functional' or profile.get('source')!={'revision':source,'binary_sha256':result.get('host_sha256')}
            or any(profile.get('checks',{}).get(name)!='passed' for name in CANDIDATE_STEPS)):
        raise ValueError('source candidate native effects or exact running executable differ')
    for name in ('host_sha256','proxy_sha256'):
        if not re.fullmatch('[a-f0-9]{64}',result.get(name,'')):raise ValueError('candidate native binary identity missing')
    if not re.fullmatch('[a-f0-9]{64}',result['candidate_cli'].get('sha256','')):raise ValueError('candidate owner identity missing')
    output.mkdir(mode=0o700)
    # Do not copy arbitrary transcripts, paths or raw fixture reports.
    closed={key:result[key] for key in ('source','accepted','signed_release_acceptance','github_credentials_present','host_sha256','proxy_sha256')}
    closed['candidate_cli']={key:result['candidate_cli'][key] for key in ('authenticated','sha256')}
    closed['profile']={key:profile[key] for key in ('ok','profile','source')}
    closed['profile']['checks']={name:'passed' for name in sorted(CANDIDATE_STEPS)}
    for name,row in [('candidate-deployment.json',closed),('cleanup.json',cleanup)]:
        (output/name).write_text(json.dumps(row,sort_keys=True)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--observations',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--source',required=True)
    args=parser.parse_args();export(args.observations,args.output,args.source)
