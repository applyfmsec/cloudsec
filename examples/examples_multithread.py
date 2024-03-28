import sys

#sys.path.append('/home/cloudsec')
#sys.path.append('/home/cloudsec/cloudsec')

sys.path.append('/Users/spadhy/git-repos/cloudsec')
sys.path.append('/Users/spadhy/git-repos/cloudsec/cloudsec')

import cvc5
from cvc5 import Kind, Term, Solver
from cloudsec.core import Policy, PolicyEquivalenceChecker
from cloudsec.cloud import http_api_policy_type


def example():
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

    # Note: p => q BUT q NOT=> p
    checker = PolicyEquivalenceChecker(policy_type=http_api_policy_type,
                                       policy_set_p=[p],
                                       policy_set_q=[q], backend='z3')

    print("~~~~~~ Example p=>q ~~~~~~")
    solver, r, found_ex,model_str = checker.p_implies_q()
    print("\n p=>q: solver: " + solver + " :"+str(r)+ " found_counter_ex: " + str(found_ex))
    print("\n model: " + str(model_str))
    print("~~~~~~ Example q=>p ~~~~~~")
    solver,r2, found_ex,model_str = checker.q_implies_p()
    print("\n q=>p: solver: " + solver + " :"+str(r2)+ " found_counter_ex: " + str(found_ex))
    print("\n model: " + str(model_str))
def example2():
    # Examples of policies

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
                                        policy_set_q=[b1, b2], backend='*')

    print("\n ~~~~~~ Example 2 p=>q ~~~~~~")
    solver, r,found_ex,model_str = checker2.p_implies_q()
    print("\n p=>q: solver: " + solver + " :"+str(r) + " found_counter_ex: " + str(found_ex))
    print("\n model: " + str(model_str))
    print("\n ~~~~~~ Example2 q=>p ~~~~~~")
    solver,r2,found_ex,model_str = checker2.q_implies_p()
    print("\n q=>p: solver: " + solver + " :"+str(r2)+ " found_counter_ex: " + str(found_ex))
    print("\n model:" + str(model_str))

#if __name__ == '__main__':
 #  print("example")
  # example()