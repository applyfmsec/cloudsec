"""
This module provides a connector for Tapis Files permissoins, stored in an instance of a 
Tapis SK, to cloudsec. 

"""
import json
import os
import sys
from tapipy.tapis import Tapis


# Add the cloudsec package directory to the python path so that 
# the tests can run easily from within the tests Docker container
sys.path.append('/home/cloudsec/cloudsec')
print(f"Python path: {sys.path}")

from core import Policy
from cloud import tapis_files_policy_type, principal, tapis_file_perm

DEV_TENANT_USERS = [f"testuser{i}" for i in range(1,21)]

base_url = os.environ.get('TAPIS_BASE_URL', "https://dev.develop.tapis.io")
jwt = os.environ.get("TAPIS_JWT")
if not jwt:
    raise Exception("Setting the TAPIS_JWT environment variable is required.")

t = Tapis(base_url=base_url, access_token=jwt)
# make sure the credential is valid:
try:
    t.systems.getSystems()
except Exception as e:
    raise Exception(f"Could not verify credential; is the token valid? Got exception: {e}")

# Tenant and Users
# A valid JSON object set in the TAPIS_INPUT variable that includes a `users` object (array of strings)
# and a `tenant` object (string) is required.
tapis_input_raw = os.environ.get("TAPIS_INPUT")
try:
    tapis_input = json.loads(tapis_input_raw)
    users = tapis_input['users']
    tenant_id = tapis_input['tenant_id']
except Exception as e:
    raise Exception(f"Unable to parse TAPIS_INPUT variable; e: {e}")

assert type(users) == list
assert type(tenant_id) == str


def get_files_perms_for_username(username, tenant_id):
    """
    Retrieve the files permissions for a specific username and tenan.
    """
    try:
        result = t.sk.getUserPerms(user=username, tenant=tenant_id)
        return result.names
    except Exception as e:
        raise Exception(f"Could not get permissions for user: {username} in tenant: {tenant_id}; e: {e}")


def convert_files_perm_to_policy(username: str, tenant: str, perm: str) -> Policy:
    """
    Converts a single Tapis SK files permission string, `perm`, belonging to a user, `username`, in `tenant`,
    to a cloudsec.core.Policy of type cloudsec.cloud.tapis_files_policy_type.
    """
    # split the perm string into its parts based on the colon. 
    # The format is: "files":<tenant>:<permission_level>:<system_id>:<path>
    # The total length is thus 5, but sometimes the <path> is left off.
    parts = perm.split(':')
    # there should at least be 4 parts and the first part should be the static string "files"
    if len(parts) < 4 or not parts[0] == 'files':
        raise Exception(f"Invalid permission record; expected at least 4 parts with first part 'files'; found: {parts}")
    perm_tenant_id = parts[1]
    perm_level = parts[2]
    perm_system_id = parts[3]
    # by default, the path is all of the system rootDir
    perm_path = "/*"
    if len(parts) >= 5:
        perm_path = parts[4]
    p = Policy(policy_type=tapis_files_policy_type, 
               principal=(tenant, username), 
               file_perm=(perm_tenant_id, perm_system_id, perm_path),
               decision="allow")
    return p


def main():
    perms = {}
    policies = []
    # check if there is a single user, "*" -- we allow this for the dev tenant.
    global users
    global tenant_id
    if len(users) == 1 and users[0] == "*" and tenant_id == "dev":
        users = DEV_TENANT_USERS
    for user in users:
        perms[user] = get_files_perms_for_username(user, tenant_id)
        print(f"Got {len(perms[user])} total permissions for {user} in tenant {tenant_id}.")
    current_policy_count = 0
    for user, ps in perms.items():
        for perm_spec in ps:
            # some of the permission records will be for different specs; e.g., apps, etc.
            if perm_spec.startswith("files"):
                policies.append(convert_files_perm_to_policy(user, tenant_id, perm_spec))
        policies_for_user = len(policies) - current_policy_count
        print(f"Generated {policies_for_user} policies for user {user}.")
        current_policy_count = len(policies)
    print(f"Total policies generated: {len(policies)}")
        
if __name__ == "__main__":
    main()