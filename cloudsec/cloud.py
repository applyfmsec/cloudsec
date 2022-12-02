# matching strategies --
from core import ExactMatching, OneWildcardMatching

# component types --
from core import StringEnumComponent, StringComponent, TupleComponent

# policies
from core import PolicyType

# constants
from core import ALPHANUM_SET, PATH_CHAR_SET

# todo -- pass in matching_type instance
exact_matching_type = ExactMatching()
tenant = StringEnumComponent(name="tenant", values=set(["a2", "a2cps", "cyverse", "vdj"]), matching_type=exact_matching_type)
one_wildcard_matching = OneWildcardMatching()
username = StringComponent(name="username", char_set=ALPHANUM_SET, max_len=25, matching_type=one_wildcard_matching)
principal = TupleComponent(name="principal", fields=[tenant, username])


service = StringEnumComponent(name="service", 
                              values=set(["systems", "files", "apps", "jobs"]), 
                              matching_type=exact_matching_type)
path = StringComponent(name="path", char_set=PATH_CHAR_SET, max_len=250, matching_type=one_wildcard_matching)
resource = TupleComponent(name="resource", fields=[tenant, service, path])
action = StringEnumComponent(name="action", 
                             values=["GET", "POST", "PUT", "DELETE"], 
                             matching_type=one_wildcard_matching)

http_api_policy_type = PolicyType(components=[principal, resource, action])



level = StringEnumComponent(name="level", 
                             values=["read", "execute", "modify"], 
                             matching_type=one_wildcard_matching)


tapis_tenant = StringEnumComponent(name="tenant_id", values=set(["a2cps", "cyverse", "dev", "vdj"]), matching_type=exact_matching_type)
tapis_system_id = StringComponent(name="system_id", char_set=ALPHANUM_SET, max_len=25, matching_type=one_wildcard_matching)
tapis_file_perm = TupleComponent(name='file_perm', fields=[tapis_tenant, tapis_system_id, path])

tapis_policy_type = PolicyType(components=[principal, resource, level])

tapis_files_policy_type = PolicyType(components=[principal, tapis_file_perm])
