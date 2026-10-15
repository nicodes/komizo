#!/usr/bin/env python3
"""Validate and export only nonsecret release acceptance evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile

from performance_acceptance import evaluate

REQUIRED_STEPS = {
    'host_global_kernel_controls_masked','public_setup','public_app_setup_idempotence',
    'public_bootstrapped_activation','public_self_upgrade','public_proxy_upgrade',
    'public_authority_interruption_recovery','cached_current_registry_stopped',
    'stop_intent_and_service_restart','fixed_budget_performance','public_onboarding',
}


def read(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>1<<20:
        raise ValueError('bounded regular evidence file required')
    return json.loads(path.read_bytes())


def validate(native, cleanup, performance, onboarding, release, source, budget):
    if native.get('version')!=1 or native.get('release')!=release or native.get('source')!=source or native.get('candidate_cli') is not None or 'candidate_cli' not in native:
        raise ValueError('exact authenticated release/source required; no local candidate')
    for field in ('cli_sha256','host_sha256','runner_sha256'):
        if not re.fullmatch('[a-f0-9]{64}',native.get(field,'')):raise ValueError('missing executable/runner identity')
    steps=native.get('steps',[])
    if len(steps)!=len(REQUIRED_STEPS) or {s['step'] for s in steps}!=REQUIRED_STEPS or not all(s.get('accepted') is True for s in steps):
        raise ValueError('every native acceptance step must pass exactly once')
    if cleanup.get('owned_container_removed') is not True or cleanup.get('shared_images_removed') is not False:
        raise ValueError('exact owned cleanup required')
    if any(native.get(k) is not expected for k,expected in {'private_cgroup_namespace':True,'host_global_kernel_controls_masked':True,'host_mounts':False,'host_docker_socket':False,'provider_calls':False,'real_data_accessed':False,'performance_accepted':True}.items()):
        raise ValueError('native isolation or scope differs')
    if performance.get('budget')!=budget or performance.get('accepted') is not True:
        raise ValueError('performance limits differ from reviewed source')
    evaluate(performance['metrics'],budget)
    if any(row.get('executable_sha256')!=native['host_sha256'] for row in performance['metrics']['control_processes']):raise ValueError('running control executable differs from accepted host')
    if onboarding.get('accepted') is not True or onboarding.get('human_interventions')!=0 or onboarding.get('provider_credentials_in_task') is not False or onboarding.get('source_checkout_in_task') is not False:
        raise ValueError('public onboarding evidence incomplete')
    if type(onboarding.get('commands')) is not int or not 4<=onboarding['commands']<=48 or not re.fullmatch('[a-f0-9]{64}',onboarding.get('public_readme_sha256','')):
        raise ValueError('bounded actual onboarding observations and public input identity required')
    if onboarding.get('mode') not in ('deterministic_public_cli','unfamiliar_agent') or onboarding['mode']!=native.get('onboarding_mode'):
        raise ValueError('onboarding observation mode differs')
    return True



def validate_bundle(directory, release, source, artifacts=None):
    summary=read(directory/'komizo-acceptance.json');performance=read(directory/'komizo-performance.json')
    if summary.get('accepted') is not True or summary.get('release')!=release or summary.get('source')!=source or summary.get('performance_sha256')!=hashlib.sha256((directory/'komizo-performance.json').read_bytes()).hexdigest():
        raise ValueError('release evidence bundle identity differs')
    validate(summary['native'],summary['cleanup'],performance,summary['onboarding'],release,source,read(Path(__file__).with_name('acceptance-budgets.json')))
    if summary['onboarding']['public_readme_sha256']!=hashlib.sha256((Path(__file__).resolve().parents[2]/'README.md').read_bytes()).hexdigest():raise ValueError('onboarding README differs from release source')
    if summary['native']['runner_sha256']!=hashlib.sha256(Path(__file__).with_name('cold-lifecycle-acceptance.py').read_bytes()).hexdigest():raise ValueError('runner differs from release source')
    if performance['budget_sha256']!=hashlib.sha256(Path(__file__).with_name('acceptance-budgets.json').read_bytes()).hexdigest():raise ValueError('budget source differs')
    if artifacts is not None:
        checks={}
        for line in (artifacts/'checksums.txt').read_text().splitlines():
            digest,name=line.split()
            if name in checks or not re.fullmatch(r'komizo_(Darwin|Linux)_(arm64|x86_64)\.tar\.gz',name) or not re.fullmatch('[a-f0-9]{64}',digest):raise ValueError('invalid release archive inventory')
            checks[name]=digest
        if len(checks)!=4:raise ValueError('all four release archives are required')
        for name,digest in checks.items():
            p=artifacts/name
            if p.is_symlink() or not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise ValueError('archive checksum differs')
        with tarfile.open(artifacts/'komizo_Linux_x86_64.tar.gz') as archive:
            entries=archive.getmembers()
            entry=archive.getmember('komizo')
            if {e.name for e in entries}!={'komizo','README.md','LICENSE'} or len(entries)!=3 or any(not e.isfile() or e.size>128<<20 for e in entries):raise ValueError('invalid accepted executable archive')
            if hashlib.sha256(archive.extractfile(entry).read()).hexdigest()!=summary['native']['cli_sha256']:raise ValueError('published executable differs from native acceptance')
    return True


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--observations',type=Path)
    mode.add_argument('--bundle',type=Path)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--artifacts',type=Path)
    parser.add_argument('--release',required=True)
    parser.add_argument('--source',required=True)
    args=parser.parse_args()
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',args.release) or not re.fullmatch('[a-f0-9]{40}',args.source):raise ValueError('exact release/source required')
    if args.bundle:
        validate_bundle(args.bundle,args.release,args.source,args.artifacts);return
    if args.output is None or args.output.exists():raise ValueError('fresh evidence destination required')
    args.output.mkdir(mode=0o755,parents=True)
    accepted=False
    try:
        native,cleanup,performance,onboarding=[read(args.observations/name) for name in ('accepted.json','cleanup.json','performance.json','onboarding.json')]
        budget=read(Path(__file__).with_name('acceptance-budgets.json'))
        validate(native,cleanup,performance,onboarding,args.release,args.source,budget)
        if onboarding['public_readme_sha256']!=hashlib.sha256((Path(__file__).resolve().parents[2]/'README.md').read_bytes()).hexdigest():raise ValueError('onboarding input source differs')
        if native['runner_sha256']!=hashlib.sha256(Path(__file__).with_name('cold-lifecycle-acceptance.py').read_bytes()).hexdigest():raise ValueError('runner source identity differs')
        if performance['budget_sha256']!=hashlib.sha256(Path(__file__).with_name('acceptance-budgets.json').read_bytes()).hexdigest():raise ValueError('budget bytes differ')
        summary={'version':1,'accepted':True,'release':args.release,'source':args.source,'native':native,'cleanup':cleanup,
                 'onboarding':{k:onboarding[k] for k in ('accepted','mode','public_readme_sha256','rejected_proposals','human_interventions','commands','seconds','inputs','provider_credentials_in_task','source_checkout_in_task')},
                 'performance_sha256':hashlib.sha256((args.observations/'performance.json').read_bytes()).hexdigest()}
        (args.output/'komizo-acceptance.json').write_text(json.dumps(summary,indent=2)+'\n')
        (args.output/'komizo-performance.json').write_bytes((args.observations/'performance.json').read_bytes())
        accepted=True
    finally:
        # No private SSH keys, fixture configuration, token environment,
        # arbitrary logs, prompts or untrusted transcript is exported.
        cleanup_status={'verified':False}
        try:
            owned=read(args.observations/'cleanup.json')
            if type(owned.get('owned_container_removed')) is bool and type(owned.get('shared_images_removed')) is bool and re.fullmatch('[a-f0-9]{64}',owned.get('cid','')):
                cleanup_status={'verified':True,**{k:owned[k] for k in ('owned_container_removed','shared_images_removed','cid')}}
        except (ValueError,OSError):pass
        (args.output/'cleanup-status.json').write_text(json.dumps(cleanup_status)+'\n')
        (args.output/'status.json').write_text(json.dumps({'accepted':accepted,'release':args.release,'source':args.source})+'\n')
        for p in args.output.iterdir():p.chmod(0o644)


if __name__=='__main__':main()
