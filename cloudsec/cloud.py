# matching strategies --
from core import ExactMatching, OneWildcardMatching

# component types --
from core import StringEnumComponent, StringComponent, TupleComponent

# policies
from core import PolicyType, Policy, PolicyEquialenceChecker

# constants
from core import ALPHANUM_SET, PATH_CHAR_SET

tenant = StringEnumComponent(name="tenant", values=set(["a2cps", "cyverse", "vdj"]), matching_type=ExactMatching)
username = StringComponent(name="username", char_set=ALPHANUM_SET, max_len=25, matching_type=OneWildcardMatching)
principal = TupleComponent(name="principal", fields=[tenant, username])


service = StringEnumComponent(name="service", 
                              values=set(["systems", "files", "apps", "jobs"]), 
                              matching_type=ExactMatching)
path = StringComponent(name="path", char_set=PATH_CHAR_SET, max_len=250, matching_type=OneWildcardMatching)
resource = TupleComponent(name="resource", fields=[tenant, service, path])
action = StringEnumComponent(name="action", 
                             values=["GET", "POST", "PUT", "DELETE"], 
                             matching_type=OneWildcardMatching)

http_api_policy_type = PolicyType(components=[principal, resource, action])
