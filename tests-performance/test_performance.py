import os
import sys

import pytest
import timeit

# Add the cloudsec package directory to the python path so that
# the tests can run easily from within the tests Docker container
sys.path.append('/home/cloudsec/cloudsec')
print(f"Python path: {sys.path}")


# matching strategies --
from core import ExactMatching, StandaloneWildcardMatching,OneWildcardMatching

from core import StringEnumComponent, StringComponent, TupleComponent

# policies
from core import PolicyType, Policy, PolicyEquivalenceChecker

# constants
from core import ALPHANUM_SET, PATH_CHAR_SET

def get_alpha_num_string_policy_type():
    one_wildcard_matching = OneWildcardMatching()
    field_1 = StringComponent(name="field_1", char_set=PATH_CHAR_SET, max_len=100, matching_type=one_wildcard_matching)
    alpha_num_string_type = PolicyType(components=[field_1])
    return alpha_num_string_type

def load_string_wild_card_policies(n: int, backend):
    alpha_num_string_policy_type = get_alpha_num_string_policy_type()
    policy_p = []
    policy_q = []
    ts_1 = timeit.default_timer()
    for i in range(n):
        # todo -- could also vary the length of the base string
        p_val = f'a1b2c3d4e5/{i}'
        # the q policy value is the p value with a * at the end.
        q_val = f'{p_val}*'
        p = Policy(policy_type=alpha_num_string_policy_type, field_1=p_val, decision="allow")
        policy_p.append(p)
        q = Policy(policy_type=alpha_num_string_policy_type, field_1=q_val, decision="allow")
        policy_q.append(q)

    ts_2 = timeit.default_timer()
    ts_dataload = ts_2 - ts_1
    ts_3 = timeit.default_timer()
    # create the policy checker for both of these
    checker = PolicyEquivalenceChecker(policy_type=alpha_num_string_policy_type, policy_set_p=policy_p, policy_set_q=policy_q,
                                            backend=backend)
    checker.encode()
    ts_4 = timeit.default_timer()
    ts_smt = ts_4 - ts_3

    return policy_p, policy_q, ts_dataload, ts_smt, checker

def test_measure_string_wc(ns=[2], filename= 'string_re_wc_results.csv',test_reps=4, backend='cvc5'):
    result = {}
    with open(filename, 'w') as f:
        f.write('StringRe Wildcard Test\n')
        f.write('n, Data Load, SMT Encoding, P => Q\n')
        for n in ns:
            result[n] = []
            for i in range(test_reps):
                #ts_1 = timeit.default_timer()
                _, _, ts_dataload, ts_smt, chk = load_string_wild_card_policies(n, backend)
                ts_2 = timeit.default_timer()
                chk.p_implies_q()
                ts_3 = timeit.default_timer()
                new_times = {'data_load': ts_dataload, 'smt_encoding': ts_smt,'p_imp_q': ts_3 - ts_2}
                result[n].append(new_times)
                f.write(f"{n}, {new_times['data_load']}, {new_times['smt_encoding']}, {new_times['p_imp_q']}\n")
    return result

def get_dynamic_enum_policy_type(N:int):
    standalone_wildcard_matching = StandaloneWildcardMatching()
    enum_values = [str(i) for i in range(N)]
    values = set(enum_values)
    denum = StringEnumComponent(name="denum", values=values, matching_type= standalone_wildcard_matching)
    dynamic_enum_policy_type = PolicyType(components=[denum])
    return dynamic_enum_policy_type

def load_enum_policies(n: int, backend):
    """
    Generate two sets of enum policies as wefor performance testing.
    """
    ts_1 = timeit.default_timer()
    policy_p = []
    dynamic_enum_policy_type = get_dynamic_enum_policy_type(N=n)
    for i in range(n):
        # create a policy allowing each possible value:
        dp = Policy(policy_type=dynamic_enum_policy_type, denum=str(i), decision="allow")
        policy_p.append(dp)

    # create a single policy with a wildcard for the enum

    policy_q = [Policy(policy_type=dynamic_enum_policy_type, denum="*", decision="allow")]
    ts_2 = timeit.default_timer()
    ts_dataload = ts_2-ts_1

    ts_3 = timeit.default_timer()
    # create the policy checker for both of these
    checker = PolicyEquivalenceChecker(policy_type=dynamic_enum_policy_type,
                                            policy_set_p=policy_p,
                                            policy_set_q=policy_q, backend=backend)
    checker.encode()
    ts_4 = timeit.default_timer()
    ts_smt = ts_4 - ts_3
    return policy_p, policy_q, ts_dataload, ts_smt, checker

def measure_enum(ns=[10, 100, 1000], filename='enum_results.csv', test_reps=4, backend='cvc5'):
    result = {}
    with open(filename, 'w') as f:
        f.write('Enum Test\n')
        f.write('n, Data Load, SMT Encoding, P => Q, Q => P\n')
        for n in ns:
            result[n] = []
            for i in range(test_reps):
                #ts_1 = timeit.default_timer()
                _, _, ts_dataload, ts_smt, chk = load_enum_policies(n, backend)
                ts_2 = timeit.default_timer()
                chk.p_implies_q()
                ts_3 = timeit.default_timer()
                chk.q_implies_p()
                ts_4 = timeit.default_timer()
                new_times = {'data_load': ts_dataload, 'smt_encoding': ts_smt, 'p_imp_q': ts_3 - ts_2, 'q_imp_p': ts_4 - ts_3}
                result[n].append(new_times)
                f.write(f"{n}, {new_times['data_load']}, {new_times['smt_encoding']}, {new_times['p_imp_q']}, {new_times['q_imp_p']}\n")
    return result
#test_measure_string_wc(ns=[2], filename='string_re_wc_results_10_1000.csv',test_reps=4, backend='cvc5')
#measure_string_wc(ns=[1000 * i for i in range(2, 26)], filename='string_re_wc_results_1000_25k.csv', test_reps=4)
