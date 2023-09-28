
from builtins import Exception, KeyError, dict, isinstance, setattr
from copy import deepcopy
from select import select
from typing import Dict, Tuple

import sys
# these are for the cloudsec container image --
sys.path.append('/home/cloudsec')
sys.path.append('/home/cloudsec/cloudsec')

z3_available = False
cvc_5_available = False

try:
    from cloudsec.backends.z3sec import Z3Backend
    z3_available = True
except ImportError as e:
    print(f"Could not import z3. The z3 backend will not be available; error details: {e}")

try:
    from cloudsec.backends.cvc5sec import CVC5Backend
    cvc_5_available = True
except ImportError as e:
    print(f"Could not import cvc5. The cvc5 backend will not be available; error details: {e}")


# Matching strategies

class BaseMatching(object):
    def __init__(self):
        self.wildcard_char = None


class ExactMatching(BaseMatching):
    """
    Represents a matching strategy where no wildcards are allowed and two values will be considered to match only if they
    are identical.
    """
    pass


class StandaloneWildcardMatching(BaseMatching):
    """
    Represents a matching strategy that is exact matching extended with a single token that matches every value. Note that this
    token cannot be combined with any other values to do partial matching.

    As an example, suppose we define a StringEnumComponent as follows:
        http_verbs = StringEnumComponent(values=["GET", "POST", "PUT", "DELETE"], matching_type=StandaloneWildcardMatching)
    
    Then, the set of all http_verbs values would be: ["GET", "POST", "PUT", "DELETE", "*"]
    where "*" matched any other value.
    """

    # StandaloneWildcardMatching is supported for enum types only while
    # OneWildcardMatching is supported for String types only. 
    def __init__(self, wildcard_char="*") -> None:
        self.wildcard_char = wildcard_char


class OneWildcardMatching(BaseMatching):
    """
    Represents a matching strategy that allows for one wildcard character to match any number of values from the value set, 
    including character substrings. In OneWildcardMatching, the wildcard character may be combined with other characters to 
    from partial matches.

    As an example, suppose we define a StringEnumComponent as follows:
        http_verbs = StringEnumComponent(values=["GET", "POST", "PUT", "DELETE"], matching_type=OneWildcardMatching)

    Then, unlike in the case of StandaloneWildcardMatching, the set of all http_verb values in this case would include values
    such as "P*", which would match both "POST" and "PUT".
    """
    # TODO -- Not implemented for enum, only implemented for String
    def __init__(self, wildcard_char="*") -> None:
        self.wildcard_char = wildcard_char


class GlobMatching(BaseMatching):
    """
    Represents a matching strategy that utilizes Unix globs.
    """
    # pass
    def __init__(self):
        raise NotImplementedError
    


class ReMatching(BaseMatching):
    """
    Represents a matching strategy that utilizes regular expressions.
    """
    # TODO -- implement in the backends
    # pass
    def __init__(self):
        raise NotImplementedError
    

# Character sets
ALPHANUM_SET = set('abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_.:')

PATH_CHAR_SET = set('abcdefghijklmnopqrstuvwxyz0123456789_/.:ABCDEFGHIJKLMNOPQRSTUVWXYZ')


# Compontent Types

class BaseComponent(object):
    pass


class StringEnumComponent(BaseComponent):
    """
    A policy component with a fixed set of string values.

    * values: the allowable values for the Enumeration. These should be strings
    * matching_type: the Python type representing the matching strategy allowed for this component. For example, pass 
        ExactMatching when equality should be used.
    """
    def __init__(self, name: str, values: "list[str]", matching_type: type):
        self.name = name
        self.values  = values

        if not isinstance(matching_type, BaseMatching):
            raise Exception()
        self.matching_type = matching_type
        self.data_type = str


class OrderedStringEnumComponent(BaseComponent):
    """
    A policy component with a fixed set of string values together with a (total) ordering of the values. Note that the ordering
    on the values of an OrderedStringEnumComponent can be used in value matching. An example is an OrderedStringEnumComponent
    that represents the "levels" of authorization; e.g., ['read', 'execute', 'write']. In this case, a permissions that allows 
    'write' access (to a resource) would match a request to 'read' (the resource) since 'read' < 'write'.

    * values: the allowable values for the Enumeration. These should be strings passed in acending order; 
              i.e., values[i] < values[j] for all i < j
    * matching_type: the Python type representing the matching strategy allowed for this component. For example, pass 
        ExactMatching when equality should be used.
    """
    def __init__(self, name: str, values: "list(str)", matching_type: type):
        raise NotImplementedError()
        # TODO --
        # self.name = name
        # self.values  = values
        # # todo -- change to look for instance
        # if not issubclass(matching_type, BaseMatching):
        #     raise Exception()
        # self.matching_type = matching_type
        # self.data_type = str


class StringComponent(BaseComponent):
    """
    A policy component with string values from a specified character set and a maximum length.

    * char_set: the allowable set of characters for the strings
    * max_len: the maximum allowable length for the strings
    * matching_type: the Python type representing the matching strategy allowed for this component. For example, pass 
        ExactMatching when equality should be used.
    """
    def __init__(self, name: str, char_set: "set(chr)", max_len: int, matching_type: type):
        self.name = name
        self.char_set  = char_set
        self.max_len = max_len
        # todo -- change to look for instance
        if not isinstance(matching_type, BaseMatching):
            raise Exception()
        self.matching_type = matching_type
        self.data_type = str


class TupleComponent(BaseComponent):
    """
    A policy component composed of a tuple of component types. The TupleComponent type is used to represent values in a policy
    that are composed of multiple, logically connected values, where each of the individual values utilize their own matching 
    strategy.

    A typical example is that of a user (i.e., "principal") in a multi-tenant system. In such a case, the principal is the
    composite data (tenant, username) where tenant is possibly a StringEnumComponent with ExactMatching and username is a
    StringComponent with (possibly) OneWildcardMatching.
    
    For example:
        tenant = StringEnumComponent(values=set(["a2cps", "cyverse", "vdj"]), matching_type=ExactMatching)
        username = StringComponent(charset=ALPHANUM_SET, matching_type=OneWildcardMatching)
        Principal = TupleComponent(fields=[tenant, username])

    """

    def __init__(self, name: str, fields: "list(BaseComponent)") -> None:
        self.name = name
        self.fields = fields
        self.data_type = tuple


class PolicyType(object):
    """
    A PolicyType represents a kind of policy in a security system. Though a security system may involve multiple policy types, 
    comparison of sets of policies generally requires the policies in the sets to all be of the same type. 
    A PolicyType defines the universe of possible values for policies of its type. A PolicyType is composed 
    of components with specific Components: i.e., Tuple, Enum, String, Bitvector, etc.

    For example, we may choose to define an HttpApiPolicyType as follows:
        tenant = StringEnumComponent(values=set(["a2cps", "cyverse", "vdj"]), matching_type=ExactMatching)
        username = StringComponent(name="username", charset=ALPHANUM_SET, matching_type=OneWildcardMatching)
        principal = TupleComponent(name="principal", fields=[tenant, username])

        service = StringEnumComponent(values=set(["systems", "files", "apps", "jobs"]), matching_type=ExactMatching)
        path = StringComponent(charset=ALPHANUM_SET, matching_type=OneWildcardMatching)
        resource = TupleComponent(fields=[tenant, service, path])

        verb = StringEnumComponent(values=["GET", "POST", "PUT", "DELETE"], matching_type=OneWildcardMatching)

        http_api_policy_type = PolicyType(components=[principal, resource, verb])
      
    """

    def __init__(self, components: "list(BaseComponent)") -> None:
        self.components = components
        for component in self.components:
            setattr(self, component.name, component)


class PolicyComponent(object):
    """
    Container for an individual policy component
    """
    pass


class PolicyComponents(object):
    """
    Container for all components comprising a policy.
    """
    pass


class Policy(object):
    """
    A Policy represents a value of a PolicyType in a security system. Policy objects have a `components` 
    attribute which in turn has an attribute named after every component in the policy. 

    For example, given:
    p = Policy(policy_type=http_api_policy_type, 
               principal=("a2cps", "jstubbs"), 
               resource=("a2cps", "systems", "s2"))
               action="GET",
               decision="allow")
    the object p has the following attributes:
    p.components = container of objects corresponding to principal, resource, verb and decision.
    p.components.principal = the principal component
    p.components.principal
    p.components.principal.data = ("a2cps", "jstubbs")  -- as a Python tuple
    p.components.decision.data = "allow"
    
    similarly, we have:
    p.components.action = the action component
    p.components.action.values = ['GET', 'POST', 'PUT', 'DELETE']
    """
    def __init__(self, policy_type: PolicyType, **kwargs) -> None:
        self.policy_type = policy_type
        self.components = PolicyComponents()
        # iterate over the components specified by the policy_type and create attributes corresponding to
        # each component and its data.
        for component in self.policy_type.components:
            # create an attribute called "component.name" on the self.components object
            setattr(self.components, component.name, deepcopy(component))
            # creating a policy requires setting the data for each component in the policy as a keyword argument
            # with name equal to the name of the component
            try:
                data = kwargs[component.name]
            except KeyError:
                raise Exception(f"Missing keyword argument ({component.name}). Please set data for all components when creating policies.")
            if not isinstance(data, component.data_type):
                raise Exception(f"Invalid data type; the component {component.name} expects data of type {component.data_type};\
                       got {type(data)}.")
            # for tuples, check the individual field types
            if type(component) == TupleComponent:
                if not len(component.fields) == len(data):
                    raise Exception(f"Incorrect number of tuple data fields for the tuple component '{component.name}'; "\
                        f"expected {len(component.fields)} values, got {len(data)} values instead.")
                for idx, f in enumerate(component.fields):
                    if not type(data[idx]) == f.data_type:
                        raise Exception(f"Invalid data type for component {idx} of the tuple component '{component.name}'; "\
                            f"expected type {f.data_type} got {type(data[idx])} instead.")
            # set an attribute called `data` on the attribute `component.name` within the components attr
            setattr(getattr(self.components, component.name), "data", data)
        # handle the special 'decision' component that all policy types use
        exact_matching = ExactMatching()
        decision = StringEnumComponent(name="decision", values=["allow", "deny"], matching_type=exact_matching)
        self.components.decision = decision
        try:
            data = kwargs['decision']
        except KeyError:
            raise Exception("Missing decision kwarg; decision is required for all policies.")
        if not data in decision.values:
            raise Exception(f"Invalid value for decision; value should be in: {decision.values}; got: {data}")
        self.components.decision.data = data
        

class PolicyEquivalenceChecker(object):
    """
    Class for checking equivalence of two sets of policies.
        policy_type: The type of policies in each list.
        policy_set_p: The first set of policies.
        policy_set_q: The second set of policies.
        backend: the solver to use for encoding and computing equivalence. Default is 'z3'.
    
    """

    def __init__(self, 
                 policy_type: PolicyType, 
                 policy_set_p: "list(Policy)", 
                 policy_set_q: "list(Policy)",
                 backend="z3"
                 ):
        
        supported_backends = set(["z3", "cvc5"])
        self.policy_type = policy_type
        self.policy_set_p = policy_set_p
        self.policy_set_q = policy_set_q
        if not backend in supported_backends:
            raise Exception(f"The specified backend ({backend}) is currently not supported; The supported "\
                f"backends include: {supported_backends}.")
        self.backend = backend
        # whether or not we hae encoded the policies yet
        self.have_encoded = False
        if self.backend == 'z3':
            if not z3_available:
                raise Exception("The z3 backend is not available on this system.")
            self.solver = Z3Backend(policy_type, policy_set_p, policy_set_q)
        if self.backend == 'cvc5':
            if not cvc_5_available:
                raise Exception("The cvc5 backend is not available on this system.")
            self.solver = CVC5Backend(policy_type, policy_set_p, policy_set_q)
    
    def encode(self):
        """
        Use `self.backend` to encode the policies.
        """
        if self.have_encoded:
            return
        self.solver.encode()
        self.have_encoded = True

    def p_implies_q(self):
        if not self.have_encoded:
            self.solver.encode()
            self.have_encoded = True
        return self.solver.p_implies_q()

    def q_implies_p(self):
        if not self.have_encoded:
            self.solver.encode()
            self.have_encoded = True
        return self.solver.q_implies_p()
        


