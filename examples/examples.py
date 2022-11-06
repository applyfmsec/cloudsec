import sys
sys.path.append('/home/cloudsec')
sys.path.append('/home/cloudsec/cloudsec')

import z3 
from core import Policy, PolicyEquialenceChecker
from cloud import http_api_policy_type

# Examples of policies
p = Policy(policy_type=http_api_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs"),
           action="GET",
           decision="allow")
      
q = Policy(policy_type=http_api_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs"),
           action="*",
           decision="allow")

a1 = Policy(policy_type=http_api_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/*"),
           action="P*",
           decision="allow")
      
a2 = Policy(policy_type=http_api_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/*"),
           action="*",
           decision="deny")

b1 = Policy(policy_type=http_api_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/*"),
           action="*",
           decision="allow")


checker = PolicyEquialenceChecker(policy_type=http_api_policy_type, 
                                  policy_set_p=[p],
                                  policy_set_q=[q])


# # Note: {a1, a2} => {b1} but {b1} NOT=> {a1,a2}
checkr2 = PolicyEquialenceChecker(policy_type=http_api_policy_type, 
                                  policy_set_p=[a1, a2],
                                  policy_set_q=[b1])

# # can call these solver methods directly; these in turn call "encode()" for the user
# checker.p_imp_q()
# checker.q_imp_p()

# # alternatively, can call encode first, if you want to delay calling the solver methods, or for fine-grained
# # performance profiling
# checker.encode()
# # 
# # . . . do some other work . . . 
# #
# # also, can do these in separate threads more efficiently after encode() has been called.
# checker.p_imp_q()
# checker.q_imp_p()


# Tests with the Z3Backend
from backends.z3sec import Z3Backend
solver = Z3Backend(http_api_policy_type, [a1, a2], [b1])
solver._encode_string_enum(a1.components.resource.fields[0], a1.components.resource.data[0])
solver._encode_string_enum(a1.components.resource.fields[1], a1.components.resource.data[1])
solver._encode_string_enum(p.components.action, p.components.action.data)
solver._encode_string(a1.components.resource.fields[2], a1.components.resource.data[2])

expr = solver._encode_tuple_parts(a1.components.resource, a1.components.resource.data)
# test the policy expr against a "real" tuple value
real_value = ["a2cps", "files", "s2/home/jstubbs/foo"]
# have to conver the real value into a z3 re as well; to do that, first convert each python string to a z3.StringVal and
# then concat them all together using z3.Concat
real_val_expr = z3.Concat( *[z3.StringVal(v) for v in real_value])

# here, we ask, "is the real_val_expr in the policy expr? (answer is Yes because policy included a wildcard)
z3.simplify(z3.InRe(real_val_expr, expr))

# note -- this throws an exception because the data type for the 3rd field in the resource component 
# is incorrect
try:
    a3 = Policy(policy_type=http_api_policy_type, 
            principal=("a2cps", "jstubbs"), 
            resource=("a2cps", "files", 7),
            action="P*",
            decision="deny")
except Exception as e:
    print(f"couldn't create a3, as expected. Error message: {e}")

# similarly, this throws an exception as well, because the principal tuple was passed the wrong number of
# components.
try:
    a3 = Policy(policy_type=http_api_policy_type, 
            principal=("a2cps", "jstubbs", "tacc"), 
            resource=("a2cps", "files", "corral/foo/bar"),
            action="P*",
            decision="deny")
except Exception as e:
    print(f"couldn't create a3, as expected. Error message: {e}")