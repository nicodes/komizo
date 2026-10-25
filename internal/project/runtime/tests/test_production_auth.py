from pathlib import Path
import subprocess
import unittest


class SyntheticIdentity(unittest.TestCase):
    def test_origins_and_session_adapter_are_explicit_caller_inputs(self):
        source = (Path(__file__).resolve().parents[1]/'helpers/production-auth.mjs').as_uri()
        script = """
import assert from 'node:assert/strict';
const { productionJourney } = await import(process.argv[1]);
let requests = 0;
globalThis.fetch = async () => { requests++; throw new Error('fixture-network'); };
process.env.CLERK_SECRET_KEY = 'sk_live_fixture';
const origin = 'https://app.example.test';
for (const options of [{}, {apiOrigin:'http://api.example.test'},
 {apiOrigin:'https://user@api.example.test'}, {apiOrigin:'https://api.example.test/path'},
 {apiOrigin:'https://api.example.test',sessionCredential:'not-an-adapter'}]) {
 await assert.rejects(productionJourney('custom-project',origin,async()=>{},options));
}
assert.equal(requests,0,'invalid caller config must fail before provider requests');
await assert.rejects(productionJourney('custom-project',origin,async()=>{},
 {apiOrigin:'https://api.example.test'}),/fixture-network/);
assert.equal(requests,1,'a new project needs no library code change');
"""
        subprocess.run(['node', '--input-type=module', '-e', script, source], check=True, timeout=30)

    def test_human_credentials_and_identity_mismatches_are_rejected(self):
        source = (Path(__file__).resolve().parents[1]/'helpers/production-auth.mjs').as_uri()
        script = '''
import assert from 'node:assert/strict';
const { verifySyntheticUser, organizationsDisabled } = await import(process.argv[1]);
const user = { id:'user_fixture',object:'user',external_id:'sampleapp-engineering-verifier',
 private_metadata:{purpose:'engineering_verification',project:'sampleapp'},
 password_enabled:false,two_factor_enabled:false,totp_enabled:false,backup_code_enabled:false,banned:false,locked:false,
 primary_email_address_id:'idn_fixture',email_addresses:[{id:'idn_fixture',email_address:'sampleapp-engineering-'+ 'a'.repeat(24)+'@example.com',reserved:true}]};
verifySyntheticUser(user,'sampleapp');
const path='/users/user_fixture/organization_memberships?limit=1';
const disabled={errors:[{code:'organization_not_enabled_in_instance'}]};
assert.equal(organizationsDisabled(403,'GET',path,disabled),true);
for (const args of [[401,'GET',path,disabled],[403,'POST',path,disabled],
  [403,'GET','/users',disabled],[403,'GET',path,{errors:[{code:'authorization_invalid'}]}],
  [403,'GET',path,null],[403,'GET',path,{errors:[...disabled.errors,...disabled.errors]}]]) {
  assert.equal(organizationsDisabled(...args),false);
}

for(const change of [{password_enabled:true},{external_id:'human'},{private_metadata:{}},{passkeys:[{}]},
 {email_addresses:[{...user.email_addresses[0],reserved:false}]}]) {
 assert.throws(()=>verifySyntheticUser({...user,...change},'sampleapp'));
}
'''
        subprocess.run(['node', '--input-type=module', '-e', script, source], check=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
