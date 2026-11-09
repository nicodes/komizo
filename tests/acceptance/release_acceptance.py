#!/usr/bin/env python3
"""Export a finite, nonsecret acceptance bundle for standalone native releases."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys
import tomllib

sys.path.insert(0,str(Path(__file__).resolve().parent))
from performance_acceptance import evaluate, SCOPE

from native_release import inventory, read as payload_read, SOURCE, TAG, PAYLOAD, CLI_NAMES

REQUIRED_STEPS={
    'apparmor_signal_delivery','apparmor_stacked_profile_enforced','apparmor_foreign_profile_signal_refused','apparmor_host_signal_refused',
    'supported_host','root_peer','forged_owner_peer','proxy_uid','proxy_mount_write_refusal',
    'proxy_process_metadata_isolation','secret_isolation','kernel_limits','unsafe_filesystem','idempotent_install',
    'managed_bootstrap_upgrade','foreign_bootstrap_bytes_refused','typed_dns_helper_refusal','native_proxy_source_receipt','unprivileged_proxy_digest_guard',
    'static_archive','service_job_dag','owner_empty_data_enrollment','nonempty_data_initialization_refused','unenrolled_production_refused',
    'mutation_replay','source_bound_https','forwarded_ip_refused','controller_death','dns_after_controller_death',
    'dns_after_other_application_stop','shared_dns_control_budget','stopped_candidate_no_jobs','application_kernel_limits',
    'cross_application_tcp_refused','same_network_tcp_allowed','installed_asset_proxy_uid_read','installed_asset_proxy_uid_write_refused',
    'failed_job_no_replay','interrupted_job_no_replay','worker_deadline','unsafe_archive','real_postgresql_api_dag',
    'immutable_postgresql_base','private_alias_delivery','job_only_secret_grant','changed_secret_bytes_refused',
    'atomic_owner_generation_rotation','coupled_rotation_failure_preserves_all_aliases','stale_generation_refused',
    'no_secret_values_in_public_outputs_or_argv','known_secret_log_redaction','owner_observation_uid_boundary',
    'preview_full_postgresql_namespace','preview_data_independence','preview_credential_independence',
    'preview_real_ttl_expiry','preview_owned_cleanup','preview_removed_start_refused','preview_fresh_graph_after_expiry','preview_reopen_initialization_once','failed_preview_scoped_remove','failed_preview_fresh_redeploy','protected_postgresql_encrypted_capture','encrypted_pair_integrity',
    'owner_postgresql_encrypted_restore','owner_side_exact_framed_exports','recovery_private_key_outside_capture_host',
    'application_pid_stress','application_memory_stress','other_application_survives_stress',
    'registry_offline_reboot','stopped_reboot_no_replay','uncertain_job_reboot_no_replay','real_reboot',
}


def bounded_bytes(path):return payload_read(path,1<<20)
def read(path):return json.loads(bounded_bytes(path))
def read_budget(path):return tomllib.loads(bounded_bytes(path).decode())
def sha(path):return hashlib.sha256(bounded_bytes(path)).hexdigest()


def validate(native,cleanup,performance,onboarding,release,source,budget):
    if (type(native.get('version')) is not int or native['version']!=1 or native.get('release')!=release or native.get('source')!=source
            or native.get('candidate_cli','missing') is not None or native.get('signed_release_acceptance') is not True):
        raise ValueError('exact authenticated standalone release/source required; no candidate')
    if set(native)!={'version','release','source','candidate_cli','signed_release_acceptance','cli_sha256','host_sha256','proxy_sha256','runner_sha256','authenticated_files','profiles','steps'}:
        raise ValueError('release observation record contains an unapproved field')
    files=native['authenticated_files']
    if not isinstance(files,dict) or set(files)!=PAYLOAD:raise ValueError('closed standalone artifact identities required')
    for name,value in files.items():
        fields={'sha256','size_bytes'}|({'executable_sha256'} if name in CLI_NAMES else set())
        if set(value)!=fields or type(value['size_bytes']) is not int or not 0<value['size_bytes']<=128<<20 or any(not re.fullmatch('[a-f0-9]{64}',value[field]) for field in fields-{'size_bytes'}):
            raise ValueError('artifact acceptance metadata is not finite and closed')
    for field in ('cli_sha256','host_sha256','proxy_sha256','runner_sha256'):
        if not re.fullmatch('[a-f0-9]{64}',native.get(field,'')):raise ValueError('missing independently verified executable identity')
    steps=native.get('steps',[])
    if len(steps)!=len(REQUIRED_STEPS) or {row['step'] for row in steps}!=REQUIRED_STEPS or any(set(row)!={'step','accepted'} or row.get('accepted') is not True for row in steps):
        raise ValueError('all native boot, data, identity, isolation and recovery controls must pass')
    if type(cleanup.get('version')) is not int or cleanup!={'version':1,'owned_guest_removed':True,'private_storage_removed':True,'shared_images_removed':False}:
        raise ValueError('exact disposable guest and private storage cleanup required')
    profiles=native.get('profiles',{})
    if set(profiles)!={'functional','bounded'}:raise ValueError('functional and bounded native profiles are both required')
    for name,report in profiles.items():
        if set(report)!={'ok','profile','source','checks'} or not isinstance(report['checks'],dict) or any(key not in REQUIRED_STEPS|{'bounded_full_postgresql_offline_reboot','fixed_budget_performance'} or value!='passed' for key,value in report['checks'].items()):
            raise ValueError('native profile exposes unapproved observation fields')
        if (report.get('ok') is not True or report.get('profile')!=name
                or report.get('source')!={'revision':source,'binary_sha256':native['host_sha256']}
                or report.get('checks',{}).get('real_reboot')!='passed'):
            raise ValueError('native profile source, exact running host or boot proof differs')
    if any(profiles['functional']['checks'].get(name)!='passed' for name in REQUIRED_STEPS):raise ValueError('functional source controls are incomplete')
    if profiles['bounded']['checks'].get('bounded_full_postgresql_offline_reboot')!='passed' or profiles['bounded']['checks'].get('fixed_budget_performance')!='passed':
        raise ValueError('bounded PostgreSQL boot or measured performance evidence is missing')
    return validate_measurements(performance,onboarding,native,budget)


def validate_measurements(performance,onboarding,identities,budget):
    if set(performance)!={'version','accepted','budget','budget_sha256','metrics','scope'}:raise ValueError('performance observation exposes unapproved fields')
    if type(performance['version']) is not int or performance['version']!=1 or performance['scope']!=SCOPE or not re.fullmatch('[a-f0-9]{64}',performance['budget_sha256']):raise ValueError('performance schema, scope or source identity differs')
    if performance.get('accepted') is not True or performance.get('budget')!=budget:raise ValueError('reviewed fixed performance budget differs')
    evaluate(performance['metrics'],budget)
    for row in performance['metrics']['control_processes']:
        expected={'controller':identities['host_sha256'],'proxy':identities['proxy_sha256']}.get(row['role'])
        if expected is not None and row['executable_sha256']!=expected:raise ValueError('running native executable differs from accepted standalone bytes')
    if (onboarding.get('accepted') is not True or onboarding.get('mode')!='deterministic_public_cli' or onboarding.get('human_interventions')!=0
            or onboarding.get('provider_credentials_in_task') is not False or onboarding.get('source_checkout_in_task') is not False
            or onboarding.get('cli_sha256')!=identities['cli_sha256'] or type(onboarding.get('seconds')) not in (int,float) or not math.isfinite(onboarding['seconds']) or onboarding['seconds']<=0 or type(onboarding.get('commands')) is not int or not 4<=onboarding['commands']<=48
            or not re.fullmatch('[a-f0-9]{64}',onboarding.get('public_readme_sha256',''))):
        raise ValueError('source-free cold public owner observations are incomplete')
    return True


def validate_bundle(directory,release,source,artifacts=None):
    summary=read(directory/'komizo-acceptance.json');performance=read(directory/'komizo-performance.json')
    if (summary.get('accepted') is not True or summary.get('release')!=release or summary.get('source')!=source
            or summary.get('performance_sha256')!=sha(directory/'komizo-performance.json')):raise ValueError('release evidence bundle identity differs')
    native=summary['native'];runner=Path(__file__).parent
    validate(native,summary['cleanup'],performance,summary['onboarding'],release,source,read_budget(runner/'acceptance-budgets.toml'))
    if native['runner_sha256']!=sha(runner/'cold-lifecycle-acceptance.py') or performance['budget_sha256']!=sha(runner/'acceptance-budgets.toml'):
        raise ValueError('acceptance runner or budget source bytes differ')
    if summary['onboarding']['public_readme_sha256']!=sha(runner.parents[1]/'README.md'):raise ValueError('public owner usage source differs')
    if artifacts is not None:
        files=inventory(artifacts,source,release)
        if files!=native['authenticated_files']:raise ValueError('standalone release files differ from independently authenticated acceptance')
        if (files['komizo_Linux_x86_64.tar.gz']['executable_sha256']!=native['cli_sha256']
                or files['komizo-box_Linux_x86_64']['sha256']!=native['host_sha256'] or files['caddy_Linux_x86_64']['sha256']!=native['proxy_sha256']):
            raise ValueError('running owner, host or proxy differs from published bytes')
    return True


def main():
    parser=argparse.ArgumentParser(description=__doc__);mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--observations',type=Path);mode.add_argument('--bundle',type=Path)
    parser.add_argument('--output',type=Path);parser.add_argument('--artifacts',type=Path)
    parser.add_argument('--release',required=True);parser.add_argument('--source',required=True);args=parser.parse_args()
    if not SOURCE.fullmatch(args.source) or not TAG.fullmatch(args.release):raise ValueError('exact release/source required')
    if args.bundle:validate_bundle(args.bundle,args.release,args.source,args.artifacts);return
    if args.output is None or args.output.exists() or args.output.is_symlink():raise ValueError('fresh evidence destination required')
    args.output.mkdir(mode=0o755,parents=True);accepted=False;cleanup={'verified':False}
    try:
        native,owned,performance,onboarding=[read(args.observations/name) for name in ('accepted.json','cleanup.json','performance.json','onboarding.json')]
        validate(native,owned,performance,onboarding,args.release,args.source,read_budget(Path(__file__).with_name('acceptance-budgets.toml')))
        result={'version':1,'accepted':True,'release':args.release,'source':args.source,'native':native,'cleanup':owned,
            'onboarding':{key:onboarding[key] for key in ('accepted','mode','commands','seconds','human_interventions','provider_credentials_in_task','source_checkout_in_task','public_readme_sha256','cli_sha256')},
            'performance_sha256':sha(args.observations/'performance.json')}
        (args.output/'komizo-acceptance.json').write_text(json.dumps(result,sort_keys=True)+'\n')
        (args.output/'komizo-performance.json').write_bytes(bounded_bytes(args.observations/'performance.json'))
        validate_bundle(args.output,args.release,args.source,args.artifacts);accepted=True
    finally:
        try:
            owned=read(args.observations/'cleanup.json')
            if type(owned.get('version')) is int and owned=={'version':1,'owned_guest_removed':True,'private_storage_removed':True,'shared_images_removed':False}:cleanup={'verified':True,**owned}
        except (ValueError,OSError):pass
        if not accepted:
            for name in ('komizo-acceptance.json','komizo-performance.json'):(args.output/name).unlink(missing_ok=True)
        (args.output/'cleanup-status.json').write_text(json.dumps(cleanup,sort_keys=True)+'\n')
        (args.output/'status.json').write_text(json.dumps({'accepted':accepted,'release':args.release,'source':args.source})+'\n')
        for path in args.output.iterdir():path.chmod(0o644)


if __name__=='__main__':main()
