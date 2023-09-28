# matching strategies --
from cloudsec.core import ExactMatching, OneWildcardMatching

# component types --
from cloudsec.core import StringEnumComponent, StringComponent, TupleComponent

# policies
from cloudsec.core import PolicyType

# constants
from cloudsec.core import ALPHANUM_SET, PATH_CHAR_SET

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
tapis_tenant = StringEnumComponent(name="tenant_id", 
                                   values=set(["a2cps", "cyverse", "dev", "vdj"]), 
                                   matching_type=exact_matching_type)
tapis_principal = TupleComponent(name="principal", fields=[tapis_tenant, username])
tapis_policy_type = PolicyType(components=[tapis_principal, resource, level])


tapis_system_id = StringComponent(name="system_id", char_set=ALPHANUM_SET, max_len=25, matching_type=one_wildcard_matching)
tapis_files_perms_level = StringEnumComponent(name="level", 
                                              values=["READ", "MODIFY"], 
                                              matching_type=one_wildcard_matching)
tapis_file_perm = TupleComponent(name='file_perm', fields=[tapis_tenant, tapis_system_id, tapis_files_perms_level, path])


tapis_files_policy_type = PolicyType(components=[tapis_principal, tapis_file_perm])


k8s_namespace = StringComponent(name="k8s_namespace", 
                                char_set=ALPHANUM_SET, 
                                max_len=50, 
                                matching_type=one_wildcard_matching)
k8s_api_group = StringEnumComponent(name="k8s_api_group", 
                                    values=set(["core", "apps"]), 
                                    matching_type=one_wildcard_matching)
k8s_resource = StringEnumComponent(name="k8s_resource", 
                                   values=set(["pod", "service", "deployment", "replicaset", "job", "daemonset",  "statefulset", "pvc", "cronjob"]), 
                                   matching_type=one_wildcard_matching)
k8s_verb = StringEnumComponent(name="k8s_verb", 
                               values=set([]), 
                               matching_type=one_wildcard_matching)
k8s_principal = TupleComponent(name="k8s_principal", fields=[k8s_namespace, username])
k8s_role = TupleComponent(name="k8s_role", fields=[k8s_namespace, ])