import os
import sys

import pytest

# Add the cloudsec package directory to the python path so that 
# the tests can run easily from within the tests Docker container
sys.path.append('/home/cloudsec/cloudsec')
print(f"Python path: {sys.path}")


# matching strategies --
from core import ExactMatching, OneWildcardMatching

from core import StringEnumComponent, StringComponent, TupleComponent

# policies
from core import PolicyType

# constants
from core import ALPHANUM_SET, PATH_CHAR_SET


def get_test_enum():
    exact_matching_type = ExactMatching()
    test_enum = StringEnumComponent(name='test_enum', 
                                    values=['val1', 'val2', 'val3'], 
                                    matching_type=exact_matching_type)
    return test_enum

def test_string_enum():
    test_enum = get_test_enum()
    assert test_enum.name == 'test_enum'
    assert test_enum.values == ['val1', 'val2', 'val3']
    assert test_enum.data_type == str
    

def get_test_str():
    exact_matching_type = ExactMatching()
    test_str = StringComponent(name='test_enum',
                               char_set=ALPHANUM_SET,
                               max_len=5,
                               matching_type=exact_matching_type)
    return test_str

def test_string():
    test_str = get_test_str()
    assert test_str.name == 'test_enum'
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


