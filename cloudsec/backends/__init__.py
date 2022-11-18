
class ImplResult(object):
    """
    Represents the result from a backend trying to prove an implication, p => q
    
    Arguments:
       - proved: Whether the backed was able to proved the statement. 
       - found_counter_ex: Whether the backend was able to find a counter example.
       - model: The counter example, as an object (e.g., an instance of z3.z3.ModelRef).
    """
    def __init__(self, proved: bool, found_counter_ex: bool, model: object):
        self.proved = proved
        self.found_counter_ex = found_counter_ex
        self.model = model


class CloudsecBackend(object):
    """
    Abstract class representing the API that all cloudsec backends should implement.
    """
    def __init__(self, policy_type, policy_set_p, policy_set_q) -> None:
        raise NotImplementedError()

    def encode(self):
        """
        Standalone method to encode the policies into the backend technology. 
        """
        raise NotImplementedError()
    
    def p_implies_q(self):
        """
        Determine whether policy_set_p implies policy_set_q. This method should call encode() if the
        policies have not already been encoded and should reuse the encodings otherwise.
        """
        raise NotImplementedError()

    def q_implies_p(self):
        """
        Determine whether policy_set_q implies policy_set_p. This method should call encode() if the
        policies have not already been encoded and should reuse the encodings otherwise.
        """
        raise NotImplementedError()        