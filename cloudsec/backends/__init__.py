
class CloudsecBackend(object):
    """
    Abstract class representing the API that all cloudsex backends should implement.
    """
    def __init__(self, policy_type, policy_set_p, policy_set_q) -> None:
        raise NotImplementedError()

    def encode(self):
        """
        Standalone method to encode the policies into the backend technology. 
        """
        raise NotImplementedError()
    
    def p_imp_q(self):
        """
        Determine whether policy_set_p implies policy_set_q. This method should call encode() if the
        policies have not already been encoded and should reuse the encodings otherwise.
        """
        raise NotImplementedError()

    def q_imp_p(self):
        """
        Determine whether policy_set_q implies policy_set_p. This method should call encode() if the
        policies have not already been encoded and should reuse the encodings otherwise.
        """
        raise NotImplementedError()        