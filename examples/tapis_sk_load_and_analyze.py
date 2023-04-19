"""
A configurable permissions load program and policy analysis demonstration the power of cloudsec.

"""
import json
import os
import requests
from tapipy.tapis import Tapis

import sys
if not '/home/cloudsec' in sys.path:
    sys.path.append('/home/cloudsec')
if not '/home/cloudsec/cloudsec' in sys.path:
    sys.path.append('/home/cloudsec/cloudsec')
from connectors import tapisfiles
from core import Policy, PolicyEquivalenceChecker
from cloud import tapis_files_policy_type


# Tapis tenant and instance to use for loading permissions and performing policy analysis.
# Configure the top three and let BASE_URL be derived from those.
TENANT_ID = "dev"
INSTANCE_URL = "develop.tapis.io"
SITE_ID = "tacc"
BASE_URL = f"https://{TENANT_ID}.{INSTANCE_URL}"

# The base URL for the corresponding admin tenant
TAPIS_SERVICE_URL = f"https://admin.{INSTANCE_URL}"

# A valid JWT for the authenticator service is required for this program. We will use it to generate
# valid JWTs for all of the users we will be using in the load program.
TAPIS_SERVICE_JWT = os.environ.get("TAPIS_SERVICE_JWT")


def get_access_token_for_user(username):
    """
    Generate an access token for `username`.
    Requires an authenticated `service_client` representing the authenticator in the TAPIS_SERVICE_URL.
    """
    url = f"{TAPIS_SERVICE_URL}/v3/tokens"
    headers = {
        "X-Tapis-User": "authenticator",
        "X-Tapis-Token": TAPIS_SERVICE_JWT,
        "X-Tapis-Tenant": "admin"
    }
    data = {
        "account_type": "user",
        "token_tenant_id": TENANT_ID,
        "token_username": username,
        "target_site_id": SITE_ID,
        # valid for 40 hours
        "access_token_ttl": 144000
    }
    try:        
        rsp = requests.post(url, json=data, headers=headers)
        rsp.raise_for_status()
    except Exception as e:
        raise Exception(f"Could not generate access totken for user {username}; details: {e}")
    return rsp.json()['result']['access_token']['access_token']


def get_tapis_client(access_token):
    """
    Generates a tapis client object for a specific access token.
    """
    return Tapis(base_url=BASE_URL, access_token=access_token)


def create_system(username, system_name, root_dir, t):
    """
    Create a tapis system owned by `username`. 
    Requires a valid Tapis client, `t`, for the user
    This
    """
    # first, check if system already exists
    try:
        t.systems.getSystem(systemId=system_name)
        # we found the system, so nothing to do
        return None
    # will raise 400 error if system doesn't exist
    except:
        pass
    
    # create the system
    system = {
        "id": f"{system_name}",
        "description": f"System {system_name} owned by {username}",
        "host": f"{system_name}.tapis-load-test.security.policies.edu",
        "systemType": "LINUX",
        "defaultAuthnMethod": "PKI_KEYS",
        "effectiveUserId": "${apiUserId}",
        "rootDir": f"{root_dir}",
        "canExec": False
    }
    t.systems.createSystem(**system, skipCredentialCheck=True)


def grant_permission(system_id, path, username, level, t):
    """
    Grant a permission to user `username` at level `level` for path, `path`on system with id `system_id`.
    `level` should be one of "READ", "MODIFY", or "*". If "*", two permissions objects will be created (one for each of
    READ and MODIFY)

    Requires a valid Tapis client, `t`, for the user owning the system. 
    """
    permissions = [level]
    if permissions[0] not in ["READ", "MODIFY", "*"]:
        raise Exception(f"Invalid level passed ({level}); valid values are READ, MODIFY and *")
    if level == "*":
        permissions = ["READ", "MODIFY"]
    for p in permissions:
        t.files.grantPermissions(systemId=system_id, path=path, username=username, permission=p)


def test_basic():
    """
    A basic test of the functions in this module and the connectors module. Can also be used from the Python
    shell to get some example objects.
    """
    user = 'sectest1'
    access_tokens = {}
    user_clients = {}
    access_tokens[user] = get_access_token_for_user(username=user)
    user_clients[user] = get_tapis_client(access_tokens[user])
    perms_dict = {}
    perms_dict[user] = tapisfiles.get_files_perms_for_username(username=user, tenant_id=TENANT_ID, t=user_clients[user])
    policies = tapisfiles.get_files_policies_for_perms(perms=perms_dict, tenant_id=TENANT_ID)
    return access_tokens, user_clients, perms_dict, policies


def generate_scenario_1():
    """
    This scenario creates 1046 paths and 5287 permissions across 1 system and 8 users.

    """
    # these are the users in our scenario
    users = {"scientists": ["test_scientist_1", "test_scientist_2"],
             "developers": ["test_developer_1", "test_developer_2"],
             "project_managers": ["test_project_manager"],
             "collaborators": ["test_project_collab_1"],
             "public": ["test_jq_public_1", "test_jq_public_2"],
    }
    # we have 1 system in this scenario
    # scientist_1 owns the system but scientist_2 also works on it.
    systems = [
        {"system_name": "zz-scenario1", 
          "root_dir": "/",
          "owner": "test_scientist_1",
        },
        # could easily add more systems if we wanted, e.g., 
        # {"system_name": "zz-scenario1-test_2", 
        #   "root_dir": "/corral-repl/projects/scenario1",
        #   "owner": "test_scientist_2",
    ]

    # source code files --
    num_libs = 5
    num_source_files = 16
    num_lib_files = 31

    # data files ---
    num_data_dirs = 11
    num_tcl_files = 11
    num_input_pngs = 21
    
    # output files -- 
    num_csv_files = 6
    num_output_pngs = 31
    generate_scenario(users, systems, num_libs, num_source_files, num_lib_files, num_data_dirs, 
                      num_tcl_files, num_input_pngs, num_csv_files, num_output_pngs)
# Total paths: 1046
# Total permissions added: 5287


def generate_scenario_2():
    """
    This scenario creates  paths and 5287 permissions across 1 system and 5 users.

    """
    # these are the users in our scenario
    users = {"scientists": ["test2_scientist_1",],
             "developers": ["test2_developer_1",],
             "project_managers": ["test2_project_manager"],
             "collaborators": ["test2_project_collab_1"],
             "public": ["test2_jq_public_1"],
    }
    # we have 1 system in this scenario
    systems = [
        {"system_name": "zz-scenario2", 
          "root_dir": "/",
          "owner": "test2_scientist_1",
        },
    ]

    # source code files --
    num_libs = 2
    num_source_files = 6
    num_lib_files = 4

    # data files ---
    num_data_dirs = 3
    num_tcl_files = 6
    num_input_pngs = 6
    
    # output files -- 
    num_csv_files = 3
    num_output_pngs = 2
    generate_scenario(users, systems, num_libs, num_source_files, num_lib_files, num_data_dirs, 
                      num_tcl_files, num_input_pngs, num_csv_files, num_output_pngs)
# Total paths: 70
# Total permissions added: 178


def generate_scenario(users, 
                      systems,
                      num_libs, 
                      num_source_files, 
                      num_lib_files, 
                      num_data_dirs, 
                      num_tcl_files, 
                      num_input_pngs, 
                      num_csv_files, 
                      num_output_pngs):
    """
    Generic function that can be called to create the systems and permissions objects for a scenario where systems
    and files permissions are created for a set of users.
    """
    # Each system has a /code, /data and a /results tree. 
    # /code is available to the scientists, the developers (READ and MODIFY) and the collaborators (READ only)
    #   - /python has .py files
    #   - /java has .java files
    #   - /python/source_i.py
    #   - /python/lib_i/source_j.py
    
    # /data is available to the scientists (READ and MODIFY)
    #   - /dir1
    #   - ...
    #   - /dirN
    # Within /results,
    #   - all files are available to the scientists (READ and MODIFY)
    #   - all files are available to developers, and project_managers (READ only)
    #   - all *.csv and *.png files are available to collaborators (READ only)
    #   - all *.png files are available to the public (READ only)
    # /results
    #   - /run1
    #   - ...
    #   - /runN
    paths = ['/code/python', '/code/java']
    
    paths.extend([f"/code/python/lib_{i}" for i in range(1, num_libs + 1)])
    paths.extend([f"/code/java/lib_{i}" for i in range(1, num_libs + 1)])
    
    paths.extend([f"/code/python/source_{j}.py" for j in range(1, num_source_files + 1)])
    paths.extend([f"/code/java/source_{j}.java" for j in range(1, num_source_files + 1)])
    
    paths.extend([f"/code/python/lib_{i}/source_{j}.py" for i in range(1, num_libs + 1) for j in range(1, num_lib_files + 1)])
    paths.extend([f"/code/java/lib_{i}/source_{j}.java" for i in range(1, num_libs + 1) for j in range(1, num_lib_files + 1)])

    paths.append('/data')
    paths.extend([f'/data/data_{i}' for i in range(1, num_data_dirs)])
    
    paths.extend([f'/data/data_{i}/input_{j}.tcl' for i in range(1, num_data_dirs) for j in range(1, num_tcl_files)])
    
    paths.extend([f'/data/data_{i}/input_{j}.png' for i in range(1, num_data_dirs) for j in range(1, num_input_pngs)])

    paths.append('/results')
    paths.extend([f'/results/run_{i}' for i in range(1, num_data_dirs)])
    
    paths.extend([f'/results/run_{i}/output_{j}.csv' for i in range(1, num_data_dirs) for j in range(1, num_csv_files + 1)])
    
    paths.extend([f'/results/run_{i}/output_{j}.png' for i in range(1, num_data_dirs) for j in range(1, num_output_pngs + 1)])

    # Add all of the Tapis objects for this scenario 
    total_permissions = 0
    for s in systems:
        # --- get a client for the owner of the system --- 
        user = s["owner"]
        access_token = get_access_token_for_user(username=user)        
        t = get_tapis_client(access_token=access_token)
        
        # --- create the system if it doesn't already exist
        create_system(username=user, system_name=s["system_name"], root_dir=s['root_dir'], t=t)

        # --- add permissions for all systems ---
        # add permissions for scientists
        for scientist in users["scientists"]:
            for p in paths:
                # all paths are READ, MODIFY for scientists
                grant_permission(system_id=s["system_name"], path=p, username=scientist, level="*", t=t)
                total_permissions += 1
        
        # add permissions for developers 
        for developer in users['developers']:
            for p in paths:
                # developers hav READ and MODIFY for all code paths
                if p.startswith("/code"):
                    grant_permission(system_id=s["system_name"], path=p, username=developer, level="*", t=t)
                    total_permissions += 1
                # developers have READ to all results paths
                elif p.startswith("/results"):
                    grant_permission(system_id=s["system_name"], path=p, username=developer, level="READ", t=t)
                    total_permissions += 1
        
        # add permissions for project managers
        for pm in users["project_managers"]:
            for p in paths:
                # PMs have READ to all results paths
                if p.startswith("/results"):
                    grant_permission(system_id=s["system_name"], path=p, username=pm, level="READ", t=t)
                    total_permissions += 1
        
        # add permissions for collaborators
        for collab in users["collaborators"]:
            for p in paths:
                # collaborators have READ for all code paths
                if p.startswith("/code"):
                    grant_permission(system_id=s["system_name"], path=p, username=collab, level="READ", t=t)
                    total_permissions += 1
                # collaborators have READ for all results csv and png files
                elif p.startswith("/results") and (p.endswith(".csv") or p.endswith(".png")):
                    grant_permission(system_id=s["system_name"], path=p, username=collab, level="READ", t=t)
                    total_permissions += 1
        
        # add permissions for the public
        for pub in users["public"]:
            for p in paths:
                if p.startswith("/results") and p.endswith(".png"):
                    grant_permission(system_id=s["system_name"], path=p, username=pub, level="READ", t=t)
                    total_permissions += 1
    
    print(f"Total paths: {len(paths)}")
    print(f"Total permissions added: {total_permissions}")


def test_scenario_1():
    users = ["test_scientist_1", "test_developer_1", "test_project_manager"]
    access_tokens = {}
    user_clients = {}
    perms_dict = {}
    for user in users:
        access_tokens[user] = get_access_token_for_user(username=user)
        user_clients[user] = get_tapis_client(access_tokens[user])
        perms_dict[user] = tapisfiles.get_files_perms_for_username(username=user, tenant_id=TENANT_ID, t=user_clients[user])
    policies = tapisfiles.get_files_policies_for_perms(perms_dict=perms_dict, tenant_id=TENANT_ID)
    # len(policies) = 3563

    # Here are some policies that we want to use to check are "correct"
    
    # scientists should have access to everything on the zz-scenario-1 system
    q1 = Policy(policy_type=tapis_files_policy_type, 
            principal=('dev', 'test_scientist_1'), 
            file_perm=('dev', 'zz-scenario1', '*', '/code/*'), 
            decision='allow')

    q2 = Policy(policy_type=tapis_files_policy_type, 
            principal=('dev', 'test_scientist_1'), 
            file_perm=('dev', 'zz-scenario1', '*', '/data/*'), 
            decision='allow')

    q3 = Policy(policy_type=tapis_files_policy_type, 
            principal=('dev', 'test_scientist_1'), 
            file_perm=('dev', 'zz-scenario1', '*', '/results/*'), 
            decision='allow')

    ch = PolicyEquivalenceChecker(policy_type=tapis_files_policy_type, policy_set_p=policies, policy_set_q=[q1,q2,q3], backend='cvc5')
    ch.encode()
    # Q has just the one allow policy which is a special case of one of the P allow policies, so Q=>P is clear:
    # result = ch.q_implies_p()

    return access_tokens, user_clients, perms_dict, policies, ch

# access_tokens, user_clients, perms_dict, policies, ch = test_scenario_1()



def test_scenario_2():
    users = ["test2_scientist_1", "test2_developer_1", "test2_project_manager"]
    access_tokens = {}
    user_clients = {}
    perms_dict = {}
    for user in users:
        access_tokens[user] = get_access_token_for_user(username=user)
        user_clients[user] = get_tapis_client(access_tokens[user])
        perms_dict[user] = tapisfiles.get_files_perms_for_username(username=user, tenant_id=TENANT_ID, t=user_clients[user])
    policies = tapisfiles.get_files_policies_for_perms(perms_dict=perms_dict, tenant_id=TENANT_ID)
    # len(policies)
    # scientists should have access to everything on the zz-scenario-1 system
    q1 = Policy(policy_type=tapis_files_policy_type, 
            principal=('dev', 'test2_scientist_1'), 
            file_perm=('dev', 'zz-scenario2', '*', '/*'), 
            decision='allow')
    # ch = PolicyEquivalenceChecker(policy_type=tapis_files_policy_type, policy_set_p=policies, policy_set_q=[q1])
    ch1 = PolicyEquivalenceChecker(policy_type=tapis_files_policy_type, policy_set_p=policies, policy_set_q=[q1], backend='cvc5')
    ch1.encode()

    # developers should have read/write access to the code but should not have any access to the data.
    r1 = Policy(policy_type=tapis_files_policy_type, 
            principal=('dev', 'test2_developer_1'), 
            file_perm=('dev', 'zz-scenario2', '*', '/code/*'), 
            decision='allow')

    r2 = Policy(policy_type=tapis_files_policy_type, 
            principal=('dev', 'test2_developer_1'), 
            file_perm=('dev', 'zz-scenario2', '*', '/data/*'), 
            decision='deny')
    ch2 = PolicyEquivalenceChecker(policy_type=tapis_files_policy_type, policy_set_p=policies, policy_set_q=[r1, r2], backend='cvc5')
    ch2.encode()

    # the project manager should not have access to the code orthe data but should have access to the results
    s1 = Policy(policy_type=tapis_files_policy_type, 
            principal=('dev', 'test2_project_manager_1'), 
            file_perm=('dev', 'zz-scenario2', '*', '/code/*'), 
            decision='deny')

    s2 = Policy(policy_type=tapis_files_policy_type, 
            principal=('dev', 'test2_project_manager'), 
            file_perm=('dev', 'zz-scenario2', '*', '/data/*'), 
            decision='deny')
    s3 = Policy(policy_type=tapis_files_policy_type, 
            principal=('dev', 'test2_project_manager'), 
            file_perm=('dev', 'zz-scenario2', 'READ', '/results/*'), 
            decision='allow')
    
    ch3 = PolicyEquivalenceChecker(policy_type=tapis_files_policy_type, policy_set_p=policies, policy_set_q=[s1, s2, s3], backend='cvc5')
    ch3.encode()

    return access_tokens, user_clients, perms_dict, policies, ch1, ch2, ch3
# access_tokens, user_clients, perms_dict, policies, ch1, ch2, ch3 = test_scenario_2()