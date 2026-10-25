#!/usr/bin/env python3
"""Allow only an independently verified, routine single-dependency update."""
import os
import re
from fnmatch import fnmatchcase

SENSITIVE = re.compile(r'clerk|pocketbase|jsonwebtoken|(?:^|[/@-])(?:auth|oauth|oidc|jwt|jose|crypto|noble|peculiar|stablelib|passport|bcrypt|scrypt|argon2|tweetnacl|libsodium|elliptic|ed25519|curve25519|rsa|openpgp|sshpk|pkijs|node-forge|firebase)(?:$|[/@-])', re.I)


def review_reason(updates, maximum=10, managed=(), sensitive=()):
    """Evaluate EVERY entry from verified bot metadata, including grouped updates.

    Group names and aggregate update types are not evidence about individual
    members. Missing metadata, unknown versions and pre-1.0 minor bumps require
    review. The caller owns additional sensitive and coordinated dependencies.
    """
    if not isinstance(updates, list) or not 1 <= len(updates) <= maximum:
        return 'missing dependency metadata or group exceeds its reviewed size limit'
    seen = set()
    for update in updates:
        if not isinstance(update, dict):
            return 'invalid dependency metadata'
        name = update.get('dependency-name')
        version = update.get('dependency-version')
        kind = update.get('update-type')
        if not isinstance(name, str) or not name or name in seen:
            return 'missing or duplicate dependency identity'
        seen.add(name)
        if any(fnmatchcase(name, pattern) for pattern in managed):
            return 'shared dependency requires a coordinated release adoption'
        if SENSITIVE.search(name) or any(fnmatchcase(name, pattern) for pattern in sensitive):
            return 'security-sensitive dependency requires review'
        match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)', version or '') if isinstance(version, str) else None
        if not match:
            return 'unknown, prerelease or digest version requires review'
        if kind not in {'version-update:semver-patch', 'version-update:semver-minor'}:
            return 'major or unknown update type requires review'
        if int(match[1]) == 0 and kind == 'version-update:semver-minor':
            return 'pre-1.0 minor update requires review'
    return None


def eligible(names, previous, new, update_type, group=''):
    dependencies = [value.strip() for value in names.split(',') if value.strip()]
    if group or len(dependencies) != 1 or SENSITIVE.search(dependencies[0]):
        return False
    if update_type not in {'version-update:semver-patch', 'version-update:semver-minor'}:
        return False
    versions = [re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)', value) for value in [previous, new]]
    if not all(versions):
        return False  # Unknown versions, prereleases and digest-only updates need review.
    old, current = [tuple(map(int, value.groups())) for value in versions]
    if current <= old or current[0] != old[0]:
        return False
    if old[0] == 0 and current[1] != old[1]:
        return False
    return True


if __name__ == '__main__':
    result = eligible(os.environ.get('DEPENDENCY_NAMES', ''), os.environ.get('PREVIOUS_VERSION', ''),
                      os.environ.get('NEW_VERSION', ''), os.environ.get('UPDATE_TYPE', ''),
                      os.environ.get('DEPENDENCY_GROUP', ''))
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write(f'eligible={str(result).lower()}\n')
    print('Routine update eligible for the full-check merge gate' if result else 'Dependency update requires review')
