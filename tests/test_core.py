import sys
import pytest
import z3

# Add the cloudsec package directory to the python path so that 
# the tests can run easily from within the tests Docker container
sys.path.append('/home/cloudsec/')
sys.path.append('/home/cloudsec/cloudsec')
print(f"Python path: {sys.path}")


# matching strategies --
from cloudsec.core import ExactMatching, OneWildcardMatching

from cloudsec.core import StringEnumComponent, StringComponent, TupleComponent

# policies
from cloudsec.core import PolicyType, Policy, PolicyEquivalenceChecker

# constants
from cloudsec.core import ALPHANUM_SET, PATH_CHAR_SET

# backends
from cloudsec.backends.z3sec import Z3Backend
from cloudsec.backends import ImplResult

def get_test_enum():
    # exact matching not supported currently for strings...
    # exact_matching_type = ExactMatching()
    one_wildcard_matching = OneWildcardMatching()
    test_enum = StringEnumComponent(name='test_enum', 
                                    values=['val1', 'val2', 'val3'], 
                                    matching_type=one_wildcard_matching)
    return test_enum

def test_string_enum():
    test_enum = get_test_enum()
    assert test_enum.name == 'test_enum'
    assert test_enum.values == ['val1', 'val2', 'val3']
    assert test_enum.data_type == str


def get_test_str():
    # exact matching not support ed currently for strings...
    # exact_matching_type = ExactMatching()
    one_wildcard_matching = OneWildcardMatching()

    test_str = StringComponent(name='test_str',
                               char_set=ALPHANUM_SET,
                               max_len=5,
                               matching_type=one_wildcard_matching)
    return test_str

def test_string():
    test_str = get_test_str()
    assert test_str.name == 'test_str'
    assert test_str.char_set == ALPHANUM_SET
    assert test_str.max_len == 5
    assert test_str.data_type == str


def get_test_tuple():
    test_enum = get_test_enum()
    test_str = get_test_str()
    test_tuple = TupleComponent(name="test_tuple", fields=[test_enum, test_str])
    return test_tuple

def test_tuple():
    test_tuple = get_test_tuple()
    assert len(test_tuple.fields) == 2
    assert test_tuple.data_type == tuple


def get_test_policy_type():
    # create a policy type with a tuple component and a path component.
    test_tuple = get_test_tuple()
    one_wildcard_matching = OneWildcardMatching()
    path = StringComponent(name="path", 
        char_set=PATH_CHAR_SET, 
        max_len=100, 
        matching_type=one_wildcard_matching)
    test_policy_type = PolicyType(components=[test_tuple, path])
    return test_policy_type

def test_policy_type():
    test_policy_type = get_test_policy_type()
    assert len(test_policy_type.components) == 2
    
    # the policy type has an attribute for every component, named after the component name.
    assert test_policy_type.path
    assert test_policy_type.test_tuple
    # these attributes have, in turn, all of the same attibutes such as name, values, etc. 
    assert test_policy_type.path.name == "path"
    # tuples have a fields attribute that is a list of the fields
    assert type(test_policy_type.test_tuple.fields) == list
    assert len(test_policy_type.test_tuple.fields) == 2
    # each field on the tuple is a component, the first component was the test_enum
    assert test_policy_type.test_tuple.fields[0].name == "test_enum"
    assert test_policy_type.test_tuple.fields[0].values == ['val1', 'val2', 'val3']
    # the second field was the test_str
    assert test_policy_type.test_tuple.fields[1].name == "test_str"
    assert test_policy_type.test_tuple.fields[1].max_len == 5


def test_policy():
    # make a couple of policies of type `test_policy_type`
    test_policy_type = get_test_policy_type()
    p = Policy(policy_type=test_policy_type, 
               path="/home/jstubbs/*", 
               test_tuple=("val1", "mystr"),
               decision="allow")    
    # policies have a `components` attribute which contains an attribute for every
    # component in the policy.
    assert p.components
    assert p.components.path
    assert p.components.test_tuple
    assert p.components.decision
    # each component has a `data` attribute which holds the data in the policy for that
    # component
    assert p.components.path.data == "/home/jstubbs/*"
    assert p.components.test_tuple.data == ("val1", "mystr")
    assert p.components.decision.data == "allow"


def test_z3_policy_checker_1():
    # make two sets of policies of type `test_policy_type` and
    # use the z3 backend to test permissiveness 
    test_policy_type = get_test_policy_type()    
    p = Policy(policy_type=test_policy_type, 
               path="/home/jstubbs/*", 
               test_tuple=("val1", "mystr"),
               decision="allow")    
    q1 = Policy(policy_type=test_policy_type, 
                path="/home/jstubbs/a.out", 
                test_tuple=("val1", "mystr"),
                decision="allow")    
    q2 = Policy(policy_type=test_policy_type, 
                path="/home/jstubbs/b.out", 
                test_tuple=("val1", "mystr"),
                decision="allow") 
    checker = PolicyEquivalenceChecker(policy_type=test_policy_type, 
                                  policy_set_p=[p],
                                  policy_set_q=[q1, q2],
                                  backend='z3')

    # note: q => p since p is more permissive. 
    solver_name, result = checker.q_implies_p()
    #result = ImplResult(proved, found_counter_ex, model_str)


    assert result.proved

    assert not result.found_counter_ex

    # note: p does not imply q since p is strictly more permissive. 
    solver_name, result = checker.p_implies_q()
    assert not result.proved
    assert result.found_counter_ex
    # the model should contain the counter example
    assert result.model is not None


def test_cvc5_policy_checker_1():
    # make two sets of policies of type `test_policy_type` and
    # use the z3 backend to test permissiveness
    test_policy_type = get_test_policy_type()
    p = Policy(policy_type=test_policy_type,
               path="/home/jstubbs/*",
               test_tuple=("val1", "mystr"),
               decision="allow")
    q1 = Policy(policy_type=test_policy_type,
                path="/home/jstubbs/a.out",
                test_tuple=("val1", "mystr"),
                decision="allow")
    q2 = Policy(policy_type=test_policy_type,
                path="/home/jstubbs/b.out",
                test_tuple=("val1", "mystr"),
                decision="allow")
    checker = PolicyEquivalenceChecker(policy_type=test_policy_type,
                                  policy_set_p=[p],
                                  policy_set_q=[q1, q2],
                                  backend='cvc5')
    # note: q => p since p is more permissive.
    solver_name, result = checker.q_implies_p(timeout=120)
    assert result.proved
    assert not result.found_counter_ex
    # note: p does not imply q since p is strictly more permissive.
    solver_name, result = checker.p_implies_q(timeout=120)
    assert not result.proved
    assert result.found_counter_ex
    # the model should contain the counter example
    assert result.model is not None
                                

def test_z3_convert_string_with_template():
    # Tests for the _check_string_part_for_var_template method of the Z3Backend.
    # first, create a z3 backend; policy_type and policy sets are required, so just pass
    # any policy type and policies:
    test_policy_type = get_test_policy_type()    
    p = Policy(policy_type=test_policy_type, 
               path="/home/jstubbs/*", 
               test_tuple=("val1", "mystr"),
               decision="allow")
    backend = Z3Backend(policy_type=test_policy_type, policy_set_p=[p], policy_set_q=[p])
    
    # Now that backend is instantiated, call _check_string_part_for_var_template() directly
    
    # check a template in the middle:
    result = backend._check_string_part_for_var_template("/home/{{ user }}/data")
    assert result == z3.Concat(z3.Re("/home/"), z3.Re(z3.String("user")), z3.Re("/data"))

    # check for a template at the end
    result = backend._check_string_part_for_var_template("/home/{{ user }}")
    assert result == z3.Concat(z3.Re("/home/"), z3.Re(z3.String("user")))

    # check for a template as the entire string
    result = backend._check_string_part_for_var_template("{{ user }}")
    assert result == z3.Re(z3.String("user"))

    # spaces don't matter on either side of the variable name
    result = backend._check_string_part_for_var_template("/home/{{ user   }}")
    assert result == z3.Concat(z3.Re("/home/"), z3.Re(z3.String("user")))

    result = backend._check_string_part_for_var_template("/home/{{   user}}")
    assert result == z3.Concat(z3.Re("/home/"), z3.Re(z3.String("user")))

    # same variable can appear twice:
    result = backend._check_string_part_for_var_template("/home/{{ user }}/data/{{ user }}")
    assert result == z3.Concat(z3.Re("/home/"), z3.Re(z3.String("user")), z3.Re("/data/"), z3.Re(z3.String("user")))

    # or different variables
    result = backend._check_string_part_for_var_template("/home/{{ user }}/data/{{ fooVar }}")
    assert result == z3.Concat(z3.Re("/home/"), z3.Re(z3.String("user")), z3.Re("/data/"), z3.Re(z3.String("fooVar")))


def test_z3_policy_checker_template():
    test_policy_type = get_test_policy_type()    
    p1 = Policy(policy_type=test_policy_type, 
               path="/home/jstubbs", 
               test_tuple=("val1", "jstubbs"),
               decision="allow")    
    p2 = Policy(policy_type=test_policy_type, 
                path="/home/spadhy", 
                test_tuple=("val1", "spadhy"),
                decision="allow")    
    q = Policy(policy_type=test_policy_type, 
                # note: the name of the variable must match cloudSec's internal naming, which is
                #       <component_name>_<field_name>
                path="/home/{{ test_tuple_test_str }}", 
                test_tuple=("val1", "{{ test_tuple_test_str }}"),
                decision="allow") 
    checker = PolicyEquivalenceChecker(policy_type=test_policy_type, 
                                  policy_set_p=[p1, p2],
                                  policy_set_q=[q],
                                  backend='z3')
    solver_name, result = checker.p_implies_q()
    assert result.proved
    assert not result.found_counter_ex

    solver_name, result = checker.q_implies_p()
    assert not result.proved
    assert result.found_counter_ex
