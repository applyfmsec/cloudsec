import sys
sys.path.append('/home/cloudsec')
sys.path.append('/home/cloudsec/cloudsec')

import z3 
from core import Policy, PolicyEquivalenceChecker
from cloud import http_api_policy_type, firewall_policy_type

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

# Note: p => q because every activity allowed by p is also allowed by q, i.e., p is less permissive than q. 
# BUT q NOT=> p, because q allows activities that p does not (for example, any action other than GET on the
# s2/home/jstubbs resource).
checker = PolicyEquivalenceChecker(policy_type=http_api_policy_type, 
                                  policy_set_p=[p],
                                  policy_set_q=[q])


a1 = Policy(policy_type=http_api_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/*"),
           action="*",
           decision="allow")

a2 = Policy(policy_type=http_api_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/*"),
           action="PUT",
           decision="deny")

a3 = Policy(policy_type=http_api_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/*"),
           action="POST",
           decision="deny")

b1 = Policy(policy_type=http_api_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/a.out"),
           action="GET",
           decision="allow")

b2 = Policy(policy_type=http_api_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/b.out"),
           action="GET",
           decision="allow")


# Note: {b1, b2} => {a1, a2, a3}    but   {a1,a2,a3}  NOT=> {b1, b2}
checker2 = PolicyEquivalenceChecker(policy_type=http_api_policy_type, 
                                  policy_set_p=[a1, a2, a3],
                                  policy_set_q=[b1, b2])

checker2.encode()

c1 = Policy(policy_type=http_api_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/a.out"),
           action="PUT",
           decision="allow")

checker3 = PolicyEquivalenceChecker(policy_type=http_api_policy_type, 
                                  policy_set_p=[a1, a2],
                                  policy_set_q=[c1])
# note that p allows all actions other than PUT on the s2/home/jstubbs/* tree (e.g., the DELETE action), so 
# p is not less permissve than q, and hence, p NOT=> q.

# On the other hand, q allows PUT:s2/home/jstubbs/a.out but p does not because of a2 (deny PUT:s2/home/jstubbs/*)
# Therefore, q is not less permissive that p, and hence, q NOT=> p here.

checker3.encode()

# here, we add an additional deny policy (a3) to the p set, which means that q is still not less
# permissive than p (and hence, q NOT=> p still).
# However, p still allows some additional actions (e.g., DELETE) on the s2/home/jstubbs/* tree, so p is
# is still not less permissive that q (and hence p NOT=> q still). 
checker4 = PolicyEquivalenceChecker(policy_type=http_api_policy_type, 
                                  policy_set_p=[a1, a2, a3],
                                  policy_set_q=[c1])

checker4.encode()


# # can call these solver methods directly; these in turn call "encode()" for the user
# checker.p_implies_q()
# checker.q_implies_p()

# # alternatively, can call encode first, if you want to delay calling the solver methods, or for fine-grained
# # performance profiling
# checker.encode()
# # 
# # . . . do some other work . . . 
# #
# # also, can do these in separate threads more efficiently after encode() has been called.
# checker.p_implies_q()
# checker.q_implies_p()


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


r = Policy(policy_type=http_api_policy_type, 
           principal=("a2", "cpsjstubbs"), 
           resource=("a2", "files", "s2/home/jstubbs"),
           action="GET",
           decision="allow")
      
s = Policy(policy_type=http_api_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2", "files", "s2/home/jstubbs"),
           action="*",
           decision="allow")

checker5 = PolicyEquivalenceChecker(policy_type=http_api_policy_type,
                                  policy_set_p=[r],
                                  policy_set_q=[s])

checker5.encode()


p6 = Policy(policy_type=firewall_policy_type,ip="11.22.33.0/24", decision="allow")
q6 = Policy(policy_type=firewall_policy_type,ip="11.22.0.0/16", decision="allow")
checker6 =  PolicyEquivalenceChecker(policy_type=firewall_policy_type,
                                  policy_set_p=[p6],
                                  policy_set_q=[q6])
checker6.encode()

'''

In [3]: result = checker6.p_implies_q()

In [4]: result.proved
Out[4]: True

In [5]: result = checker6.q_implies_p()

In [6]: result.proved
Out[6]: False

In [7]: result.model
Out[7]: [ip_c = 222, ip_a = 11, ip_b = 22]

'''

#p = Policy(policy_type=http_api_policy_type,
#    principal=("a2cps", "jdoe"),
#    resource=("a2cps", "files",
#              "/ls6/home/jdoe"),
#    action="GET",
#    decision="allow")
