"""Export bounded nonsecret provisional deployment observations."""
import argparse
import json
from pathlib import Path
import re

def export(observations, output, source):
 if not re.fullmatch('[a-f0-9]{40}',source) or output.exists(): raise ValueError('exact source and fresh output required')
 rows={}
 for name in ('candidate-deployment.json','cleanup.json'):
  p=observations/name
  if p.is_symlink() or not p.is_file() or p.stat().st_size>1<<20:raise ValueError('bounded regular evidence required')
  rows[name]=json.loads(p.read_bytes())
 result=rows['candidate-deployment.json'];cleanup=rows['cleanup.json']
 if result['source']!=source or not result['accepted'] or result['signed_release_acceptance'] or result['candidate_cli']['authenticated'] or result['github_credentials_present'] or not cleanup['owned_container_removed'] or cleanup['shared_images_removed']:raise ValueError('candidate identity, isolation or cleanup differs')
 required={'public_setup','public_app_setup_idempotence','public_owner_approved_activation','public_update_and_rollback'}
 if not required <= {s['step'] for s in result['steps'] if s.get('accepted') is True}:raise ValueError('deployment observations missing')
 output.mkdir(mode=0o700)
 for name,row in rows.items():(output/name).write_text(json.dumps(row,indent=2)+'\n')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--observations',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--source',required=True)
 a=p.parse_args();export(a.observations,a.output,a.source)
