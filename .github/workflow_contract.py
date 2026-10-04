#!/usr/bin/env python3
"""Validate a caller-owned workflow catalogue; no application or fleet mappings."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import yaml

CATALOGUE = {
    'ci.yml': 'CI', 'cd.yml': 'CD', 'pr-preview.yml': 'PR Preview',
    'dependency-maintenance.yml': 'Dependency Maintenance',
    'dependency-policy.yml': 'Dependency Policy', 'security-scan.yml': 'Security Scan',
    'production-verification.yml': 'Production Verification', 'backup.yml': 'Backup',
    'recovery.yml': 'Recovery', 'production-diagnostics.yml': 'Production Diagnostics',
    'release.yml': 'Release', 'fleet-audit.yml': 'Fleet Audit',
}
PR_TYPES = {'opened', 'synchronize', 'reopened', 'ready_for_review'}

class Loader(yaml.SafeLoader):
    yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for key in list(Loader.yaml_implicit_resolvers):
    Loader.yaml_implicit_resolvers[key] = [(tag, pattern) for tag, pattern in
        Loader.yaml_implicit_resolvers[key] if tag != 'tag:yaml.org,2002:bool']
Loader.add_implicit_resolver('tag:yaml.org,2002:bool', re.compile(r'^(?:true|false)$', re.I), list('tTfF'))

def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result: raise ValueError(f'duplicate YAML key: {key}')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result
Loader.add_constructor('tag:yaml.org,2002:map', unique_mapping)

def load(path):
    data = yaml.load(Path(path).read_text(), Loader=Loader)
    if not isinstance(data, dict): raise ValueError(f'{path}: workflow must be a mapping')
    return data

def triggers(document):
    value = document.get('on', {})
    if isinstance(value, str): return {value: None}
    if isinstance(value, list): return dict.fromkeys(value)
    if not isinstance(value, dict): raise ValueError('workflow triggers must be a mapping or event list')
    return value

def validate(root):
    root = Path(root); policy = json.loads((root/'.github/workflow-contract.json').read_text())
    if set(policy.get('engine_sha256', {})) != {'workflow_contract.py', 'workflow_operation.py', 'pins_compat.mjs'}: raise ValueError('complete generic engine hashes required')
    if policy.get('version') != 1: raise ValueError('unknown workflow contract version')
    for filename, expected in policy['engine_sha256'].items():
        if filename not in {'workflow_contract.py', 'workflow_operation.py', 'pins_compat.mjs'}:
            raise ValueError('unknown generic workflow engine file')
        path = root/'.github'/filename
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f'generic engine bytes differ: {filename}')
    folder = root/'.github/workflows'
    actual = {p.name for p in folder.iterdir() if p.suffix in {'.yml', '.yaml'}}
    required = set(policy['required']); legacy = policy.get('legacy_apis', {})
    if not required <= CATALOGUE.keys(): raise ValueError('unknown required workflow purpose')
    if actual != required | legacy.keys():
        raise ValueError(f'workflow inventory differs: missing {sorted(required-actual)}, unexpected {sorted(actual-required-legacy.keys())}')
    documents = {}
    for name in sorted(actual):
        if (folder/name).is_symlink(): raise ValueError('workflow files must not be symlinks')
        document = load(folder/name); documents[name] = document
        expected = legacy.get(name, CATALOGUE.get(name))
        if document.get('name') != expected: raise ValueError(f'{name}: expected display name {expected}')
        events = triggers(document)
        if not document.get('jobs'): raise ValueError(f'{name}: no real jobs')
        if name == 'ci.yml':
            if 'pull_request' not in events or 'workflow_dispatch' not in events:
                raise ValueError('CI requires pull_request and workflow_dispatch')
            if not PR_TYPES <= set((events['pull_request'] or {}).get('types', [])):
                raise ValueError('CI must include every required PR lifecycle event')
            if policy['kind'] == 'product' and 'push' in events:
                raise ValueError('product CI must not duplicate main CD verification')
            names = {j.get('name', key) for key, j in document['jobs'].items()}
            if not set(policy.get('ci_gates', [])) <= names: raise ValueError('required CI gates missing')
        if name == 'pr-preview.yml':
            types = set((events.get('pull_request') or {}).get('types', []))
            if not PR_TYPES | {'closed'} <= types: raise ValueError('preview lifecycle lacks ready or cleanup event')
        if name == 'cd.yml':
            if 'workflow_dispatch' not in events or (events.get('push') or {}).get('branches') != ['main']:
                raise ValueError('CD requires main-only push and manual dispatch')
            group = document.get('concurrency', {})
            if group.get('cancel-in-progress') is not False: raise ValueError('deployment cancellation must remain disabled')
        if name in {'recovery.yml', 'production-diagnostics.yml'} and set(events) != {'workflow_dispatch'}:
            raise ValueError(f'{name}: operator operations must be manual only')
        for key, job in document['jobs'].items():
            if 'steps' not in job and 'uses' not in job: raise ValueError(f'{name}/{key}: no implementation')
            if 'pull_request_target' in events:
                for step in job.get('steps', []):
                    checkout = str(step.get('uses','')).startswith('actions/checkout@')
                    ref = str(step.get('with',{}).get('ref',''))
                    if checkout and ('pull_request.head' in ref or 'head_ref' in ref):
                        raise ValueError('privileged policy cannot check out untrusted PR source')
    operations = root/'.github/workflow-operations.json'
    if operations.exists():
        for name, spec in json.loads(operations.read_text()).items():
            if not spec.get('commands'): raise ValueError(f'{name}: empty workflow operation')
            for command in spec['commands']:
                if not isinstance(command, list) or not command or not all(isinstance(x,str) and x for x in command):
                    raise ValueError(f'{name}: commands must be nonempty argv lists')
                if command[0] in {'echo','true',':'}: raise ValueError(f'{name}: successful placeholder is not an operation')
    return documents

def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', default='.')
    args=parser.parse_args(); documents=validate(args.root)
    print(f'Workflow contract passed: {len(documents)} workflows')
if __name__ == '__main__':
    try: main()
    except (ValueError, KeyError, OSError, yaml.YAMLError) as error:
        print(f'Workflow contract failed: {error}', file=sys.stderr);sys.exit(1)
