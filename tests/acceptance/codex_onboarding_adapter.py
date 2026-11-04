#!/usr/bin/env python3
"""Optional Codex adapter; no model call is part of normal release acceptance."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    task=json.loads(sys.stdin.buffer.read(1<<20))
    with tempfile.TemporaryDirectory(prefix='komizo-public-onboarding-') as temp:
        root=Path(temp)
        schema={'type':'object','properties':{'argv':{'type':'array','items':{'type':'string'}}},'required':['argv'],'additionalProperties':False}
        (root/'schema.json').write_text(json.dumps(schema))
        flags=[]
        for feature in ('shell_tool','unified_exec','plugins','apps','browser_use','computer_use','hooks','image_generation'):
            flags+=['--disable',feature]
        args=['codex','exec','--ignore-user-config','--ignore-rules','--ephemeral','--skip-git-repo-check','--sandbox','read-only',
              '--cd',temp,'--json','--output-schema',str(root/'schema.json'),'--output-last-message',str(root/'answer.json'),
              '-c','project_doc_max_bytes=0','-c','web_search="disabled"',*flags,'-']
        result=subprocess.run(args,input=json.dumps(task).encode(),capture_output=True,timeout=150)
        if result.returncode:
            # Do not forward auth/config diagnostics into the public transcript.
            raise RuntimeError('Codex adapter failed; inspect the local operator session')
        for line in result.stdout.splitlines():
            event=json.loads(line)
            item=event.get('item',{})
            if item.get('type') not in (None,'reasoning','agent_message'):
                raise RuntimeError('tool use invalidates the public-input-only experiment')
        answer=json.loads((root/'answer.json').read_bytes())
        print(json.dumps(answer))


if __name__=='__main__':main()
