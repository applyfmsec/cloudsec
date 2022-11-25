import sys
import pytest

# Add the cloudsec package directory to the python path so that 
# the tests can run easily from within the tests Docker container
sys.path.append('/home/cloudsec/cloudsec')
print(f"Python path: {sys.path}")

from core import PolicyType, Policy, PolicyEquivalenceChecker
from cloud import tapis_policy_type


def get_policy_sets_1():
    p1 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/*"),
           level="read",
           decision="allow")

    q1 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/a.out"),
           level="read",
           decision="allow")    
    q2 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/b.out"),
           level="read",
           decision="allow")
    return [p1], [q1, q2]


def test_tapis_policy_set_1a_z3():
    P, Q = get_policy_sets_1()
    # note: q => p because p allows read to everything in /home/jstubbs
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q, 
                                  backend='z3')
    checker.encode()
    
    result = checker.p_implies_q()
    assert not result.proved
    assert result.found_counter_ex
    assert result.model


def test_tapis_policy_set_1a_cvc5():
    P, Q = get_policy_sets_1()
    # note: q => p because p allows read to everything in /home/jstubbs
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q, 
                                  backend='cvc5')
    checker.encode()
    
    result = checker.p_implies_q()
    assert not result.proved
    assert result.found_counter_ex
    assert result.model


def test_tapis_policy_set_1b_z3():
    P, Q = get_policy_sets_1()
    # note: q => p because p allows read to everything in /home/jstubbs
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='z3')
    checker.encode()    
    result = checker.q_implies_p()
    assert result.proved
    assert not result.found_counter_ex


def test_tapis_policy_set_1b_cvc5():
    P, Q = get_policy_sets_1()
    # note: q => p because p allows read to everything in /home/jstubbs
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='cvc5')
    checker.encode()    
    result = checker.q_implies_p()
    assert result.proved
    assert not result.found_counter_ex


def get_policy_sets_2():
    # give read access to every file in the directory
    p1 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/*"),
           level="read",
           decision="allow")
    # give all accesses to every .py file
    p2 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/*.py"),
           level="write",
           decision="allow")
    p3 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/*.py"),
           level="execute",
           decision="allow")

    p4 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/*.py"),
           level="read",
           decision="allow")
    
    # check specific accesses
    q1 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/a1.py"),
           level="execute",
           decision="allow")    
    q2 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/a2.out"),
           level="read",
           decision="allow")
    q3 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/a2.py"),
           level="write",
           decision="allow")
    return [p1, p2, p3, p4], [q1, q2, q3]


def test_tapis_policy_set_2_z3():
    # note: q => p because p allows all access to all python files
    P, Q = get_policy_sets_2()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='z3')
    checker.encode()
    
    result = checker.q_implies_p()
    assert result.proved
    assert not result.found_counter_ex


def test_tapis_policy_set_2_cvc5():
    # note: q => p because p allows all access to all python files
    P, Q = get_policy_sets_2()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='cvc5')
    checker.encode()
    
    result = checker.q_implies_p()
    assert result.proved
    assert not result.found_counter_ex


def get_policy_sets_3():
    # here, we simply add a fourth policy to the q set.
    P, Q = get_policy_sets_2()
    # however, adding a policy wih execute on a non-python file within /home/jstubbs 
    # should produce a counter example.
    q4 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/a2.out"),
           level="execute",
           decision="allow")
    Q.append(q4)
    return P, Q


def test_tapis_policy_set_3_z3():
    # note: q NOT=> p because q allows execute access to a .out file
    P, Q = get_policy_sets_3()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='z3')
    checker.encode()
    result = checker.q_implies_p()
    assert not result.proved
    assert result.found_counter_ex
    assert result.model


def test_tapis_policy_set_3_cvc5():
    # note: q NOT=> p because q allows execute access to a .out file
    P, Q = get_policy_sets_3()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='cvc5')
    checker.encode()
    result = checker.q_implies_p()
    assert not result.proved
    assert result.found_counter_ex
    assert result.model


def get_policy_sets_4():
    # grant user jstubbs all access
    p1 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/*"),
           level="*",
           decision="allow")
    # grant user jdoe read access to all files except the .py files
    p2 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jdoe"), 
           resource=("a2cps", "files", "s2/home/jstubbs/*"),
           level="read",
           decision="allow")
    p3 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jdoe"), 
           resource=("a2cps", "files", "s2/home/jstubbs/*.py"),
           level="read",
           decision="deny")
    # grant every user read access to the README
    p4 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "*"), 
           resource=("a2cps", "files", "s2/home/jstubbs/readme.md"),
           level="read",
           decision="allow")
    # users in a different tenant have no access
    q1 = Policy(policy_type=tapis_policy_type, 
           principal=("vdj", "jstubbs"), 
           resource=("a2cps", "files", "s2/home/jstubbs/readme.md"),
           level="read",
           decision="allow")
    return [p1, p2, p3, p4], [q1]


def test_tapis_policy_set_4_z3():
    P, Q = get_policy_sets_4()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='z3')
    checker.encode()
    result = checker.q_implies_p()
    assert not result.proved
    assert result.found_counter_ex
    assert result.model


def test_tapis_policy_set_4_cvc5():
    P, Q = get_policy_sets_4()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='cvc5')
    checker.encode()
    result = checker.q_implies_p()
    assert not result.proved
    assert result.found_counter_ex
    assert result.model


def get_policy_sets_5():
    # use the P policy set from 4 but change the Q policy set
    P, _ = get_policy_sets_4()

    # user jdoe can read non python files
    r1 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jdoe"), 
           resource=("a2cps", "files", "s2/home/jstubbs/foo.txt"),
           level="read",
           decision="allow")
    return P, [r1]
    

def test_tapis_policy_set_5_z3():
    P, Q = get_policy_sets_5()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='z3')
    checker.encode()
    result = checker.q_implies_p()
    assert result.proved
    assert not result.found_counter_ex


def test_tapis_policy_set_5_cvc5():
    P, Q = get_policy_sets_5()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='cvc5')
    checker.encode()
    result = checker.q_implies_p()
    assert result.proved
    assert not result.found_counter_ex


def get_policy_sets_6():
    # use the P policy set from 4 but change the Q policy set
    P, _ = get_policy_sets_4()

    # a random other user in the tenant can read the readme.md
    s1 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jsmith"), 
           resource=("a2cps", "files", "s2/home/jstubbs/readme.md"),
           level="read",
           decision="allow")
    return P, [s1]


def test_tapis_policy_set_6_z3():
    P, Q = get_policy_sets_6()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='z3')
    checker.encode()
    result = checker.q_implies_p()
    assert result.proved
    assert not result.found_counter_ex


def test_tapis_policy_set_6_cvc5():
    P, Q = get_policy_sets_6()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='cvc5')
    checker.encode()
    result = checker.q_implies_p()
    assert result.proved
    assert not result.found_counter_ex


def get_policy_sets_7():
    # use the P policy set from 4 but change the Q policy set
    P, _ = get_policy_sets_4()

    # a random other user in the tenant can read the readme.md
    t1 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jsmith"), 
           resource=("a2cps", "files", "s2/home/jstubbs/readme.md"),
           level="read",
           decision="allow")
    # but that user cannot read anything else
    t2 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jsmith"), 
           resource=("a2cps", "files", "s2/home/jstubbs/foo.txt"),
           level="read",
           decision="deny")
    t3 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jsmith"), 
           resource=("a2cps", "files", "s2/home/jstubbs/bar.py"),
           level="read",
           decision="deny")
    t4 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jsmith"), 
           resource=("a2cps", "files", "s2/home/jstubbs/baz.out"),
           level="read",
           decision="deny")
    return P, [t1, t2, t3, t4]


def test_tapis_policy_set_7_z3():
    P, Q = get_policy_sets_7()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='z3')
    checker.encode()
    result = checker.q_implies_p()
    assert result.proved
    assert not result.found_counter_ex


def test_tapis_policy_set_7_cvc5():
    P, Q = get_policy_sets_7()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='cvc5')
    checker.encode()
    result = checker.q_implies_p()
    assert result.proved
    assert not result.found_counter_ex


def get_policy_sets_8():
    # use the P policy set from 4 but change the Q policy set
    P, _ = get_policy_sets_4()
    # here, we deny jsmith read access to everything in /home/jstubbs except we explicitly
    # state that jsmith has access to the readme. 
    # since jsmith should have read access to the readme, this policy is less
    # permissive than P. therefore, Q => P in this case
    u1 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jsmith"), 
           resource=("a2cps", "files", "s2/home/jstubbs/*"),
           level="read",
           decision="deny")
    u2 = Policy(policy_type=tapis_policy_type, 
           principal=("a2cps", "jsmith"), 
           resource=("a2cps", "files", "s2/home/jstubbs/readme.md"),
           level="read",
           decision="allow")
    return P, [u1, u2]


def test_tapis_policy_set_8_z3():
    P, Q = get_policy_sets_8()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='z3')
    checker.encode()
    result = checker.q_implies_p()
    assert result.proved
    assert not result.found_counter_ex
    assert not result.model


def test_tapis_policy_set_8_cvc5():
    P, Q = get_policy_sets_8()
    checker = PolicyEquivalenceChecker(policy_type=tapis_policy_type, 
                                  policy_set_p=P,
                                  policy_set_q=Q,
                                  backend='cvc5')
    checker.encode()
    result = checker.q_implies_p()
    assert result.proved
    assert not result.found_counter_ex
    assert not result.model

