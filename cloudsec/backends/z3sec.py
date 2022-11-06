"""
A cloudsec backend based on the z3 SMT solver.
"""


import z3

from cloudsec.backends import CloudsecBackend



class Z3Backend(CloudsecBackend):

    def __init__(self, policy_type, policy_set_p, policy_set_q) -> None:
        self.policy_type = policy_type
        self.policy_set_p = policy_set_p
        self.policy_set_q = policy_set_q


    def _create_bool_encoding(self, name, expr):
        free_var = z3.String(name)
        return z3.InRe(free_var, expr)


    def _get_string_enum_expr(self, string_enum_component_type, value):
        values = string_enum_component_type.values
        z_all_vals_re_ref = z3.Union([z3.Re(z3.StringVal(v)) for v in values])
        # todo -- at this point in time, we do not distinguish the different matching types, but
        #         we will in a future release.
        try:
            wildcard = string_enum_component_type.matching_type.wildcard_char
        except:
            print("Warning -- did not find the `wildcard_char` on the matching_type; defaulting to '*'.")
            wildcard = "*"

        if value == wildcard:
            return z_all_vals_re_ref
        if value not in values:
            message=f"value {value} is not allowed for enum type {string_enum_component_type.name}; allowed values are {values}"
            raise Exception(message)
        return z3.Re(z3.StringVal(value))

    
    def _encode_string_enum(self, string_enum_component_type, value):
        """
        Encodes a StringEnumComponent type into a z3 boolean expression.

        string_component_type: An instance of StringEnumComponent
        value: the data associated with the policy for this component. 
        
        """
        expr = self._get_string_enum_expr(string_enum_component_type, value)
        return self._create_bool_encoding(string_enum_component_type.name, expr)
        
    
    def _get_string_expr(self, string_component_type, value):
        charset = string_component_type.char_set
        # todo -- at this point in time, we do not distinguish the different matching types, but
        #         we will in a future release.
        try:
            wildcard = string_component_type.matching_type.wildcard_char
        except:
            print("Warning -- did not find the `wildcard_char` on the matching_type; defaulting to '*'.")
            wildcard = "*"
        # create
        z_all_vals_re_ref = z3.Star(z3.Union([z3.Re(z3.StringVal(c)) for c in charset]))
        # check that the value is contained within the charset plus the * character
        if not charset.union(set('*')).intersection(set(value)) == set(value):
            raise Exception(f"Data must be contained within the charset for this StringComponent ({string_component_type.name}).")
        if value == wildcard:
            return z_all_vals_re_ref
        if not wildcard in value:
            return z3.Re(z3.StringVal(value))
        parts = value.split('*')
        # compute the first one since Concat requires at least two args.
        result = z3.Concat(z3.Re(z3.StringVal(parts[0])), z_all_vals_re_ref)
        # handle the case of str containing a single * in the last char
        if len(parts) == 2 and value[-1] == wildcard:
            return result
        for idx, part in enumerate(parts[1:]):
            # it is possible the str ends in a '*', in which case we only need to add a single re_all_chars,
            # unless we already did because this is the
            if part == '':
                if idx == 0:
                    return result
                return z3.Concat(result, z_all_vals_re_ref)
            # handle whether this is the final part or not:
            if idx + 2 == len(parts):
                return z3.Concat(result, z3.Re(z3.StringVal(part)))
            result = z3.Concat(result, z3.Re(z3.StringVal(part)))
        return result

    def _encode_string(self, string_component_type, value):
        """
        Encodes a StringComponent type into a z3 boolean expression.

        string_component_type: An instance of StringComponent
        value: the data associated with the policy for this component. 
        """
        expr = self._get_string_expr(string_component_type, value)
        return self._create_bool_encoding(string_component_type.name, expr)

    def _encode_tuple_parts(self, tuple_component_type, value):
        res = []
        for idx, field in enumerate(tuple_component_type.fields):
            val = value[idx]
            # check the type of each field and call the appropriate _encode method...
            # StringComponents have a char_set and mex_len
            if hasattr(field, "char_set") and hasattr(field, "max_len"):
                result = self._get_string_expr(field, val)
            elif hasattr(field, "values"):
                result = self._get_string_enum_expr(field, val)
            res.append(result)
        return z3.Concat(*res)


    def _encode_tuple(self, tuple_component_type, value):
        expr = self._encode_tuple_parts(tuple_component_type, value)
        return self._create_bool_encoding(tuple_component_type.name, expr)
        

    def encode(self):
        pass