"""
A cloudsec backend based on the z3 SMT solver.
"""


import z3

from cloudsec.backends import CloudsecBackend, ImplResult

# Whether to support template variables within the values of policy components;
SUPPORT_TEMPLATE_VARIABLES = True

# Left and right delimiters for template variables
TEMPLATE_LEFT_DL = '{{'
TEMPLATE_RIGHT_DL = '}}'


class Z3Backend(CloudsecBackend):
    """
    CloudSec backend implemented with the Z3 solver.
    """

    def __init__(self, policy_type, policy_set_p, policy_set_q) -> None:
        self.policy_type = policy_type
        self.policy_set_p = policy_set_p
        self.policy_set_q = policy_set_q


    def _create_bool_encoding(self, name, expr):
        """
        Create a z3 boolean encoding of the expression, `expr`.
        `name` should be the name to use for the free variable (i.e., the name of the component).
        
        This should be the last method called when encoding a component. 
        """
        component_free_var = z3.String(name)
        return z3.InRe(component_free_var, expr)


    def _check_string_part_for_var_template(self, string_part):
        """
        Checks a string, `string_part`, to see if it contains one or more template variables, 
        delimited by TEMPLATE_LEFT_DL and TEMPLATE_RIGHT_DL. Replace all instances of
        any template variable found with an actual z3 free variable. Returns a z3 Re expression.

        For example, given:  `string_part` = "s2/home/{{ user }}/MyData"
        this function returns:   z3.Concat(z3.Re('/home/'), z3.Re(user), z3.Re('/MyData'))
        where user = z3.String("user")
        
        If `string_part` does not contain any instances of template variables, then the entire 
        `string_part` wrapped in an Re is returned.
        For example, given `string_part` = "/home/jstubbs"
        this function returns: z3.Re(z3.StringVal('/home/jstubbs')

        Notes: 1) we strip any spaces between the delimiters
               2) there could be multiple occurrences of a variable, but using the same name in the 
                  construction of the z3 variables results in the same free var.

        """
        # current_str tracks the portion of the string_part we are working on in the loop
        # we move from left to right, adding portions from the left to the "result" object and
        # removing them from the current_str
        current_str = string_part
        # the list of results that will ultimately be concatenated together 
        result = []
        while len(current_str) > 0:
            left_idx = current_str.find(TEMPLATE_LEFT_DL)
            if left_idx == -1:
                # we didn't find a left delimiter, so we are done
                new_result = z3.Re(z3.StringVal(current_str))
                if len(result) == 0:
                    return new_result
                else:
                    result.append(new_result)
                    return z3.Concat(*result)
            # we found a left delimiter, look for the matching right delimiter.
            # the left_idx contains the index of the first character in the left delimiter
            # so idx_var_name contains the index of the first character (including spaces) of
            # the variable name
            left_idx_var_name = left_idx + len(TEMPLATE_LEFT_DL)
            # look beyond that for the first right delimiter
            right_idx = current_str[left_idx_var_name:].find(TEMPLATE_RIGHT_DL)
            if right_idx == -1:
                # we didn't find a matching right delimiter; we have to blow up
                message = f"The value {string_part} contained a left delimiter in position {left_idx} with no matching right delimiter."
                raise Exception(message)
            # We found the right delimiter at position right_idx beyond left_idx_var_name, so
            # the variable name (including spaces) lives between those
            right_idx_var_name = left_idx_var_name + right_idx
            # remove spaces off the end -- note that the variable name could still have spaces in between, 
            # but z3 is OK with this.
            var_name = current_str[left_idx_var_name:right_idx_var_name].strip()
            # we blow up if the var name contains another left delimiter, as this seems erroneous
            if TEMPLATE_LEFT_DL in var_name:
                message = f"The value {string_part} contained the variable {var_name} that included another left delimiter. Variable names should be alphanumeric."
                raise Exception(message)
            
            z3_var = z3.String(var_name)
            # we are ready to add parts to the result. there are a few cases
            # first, it is possible the entire current_str was just a variable:
            if left_idx == 0 and len(TEMPLATE_LEFT_DL) + right_idx + len(TEMPLATE_RIGHT_DL)== len(current_str):
                new_result = z3.Re(z3_var)
                if len(result) == 0:
                    return new_result
                else:
                    result.append(new_result)
                    return z3.Concat(*result)
            # otherwise, either the left side or the right side (or both) had parts.
            if left_idx > 0:
                # the left side should be all string literal here
                result.append(z3.Re(current_str[:left_idx]))
            # append the new free var
            result.append(z3.Re(z3_var))
            # remove everything up to the right delimiter from the current_str and repeat
            previous_str = left_idx + len(TEMPLATE_LEFT_DL) + right_idx + len(TEMPLATE_RIGHT_DL)
            current_str = current_str[previous_str:]
            if len(current_str) == 0:
                return z3.Concat(*result)

            
    def _get_string_enum_expr(self, string_enum_component_type, value):
        values = string_enum_component_type.values
        z_all_vals_re_ref = z3.Union([z3.Re(z3.StringVal(v)) for v in values])
        # todo -- at this point in time, we do not distinguish the different matching types, but
        #         we will in a future release.
        try:
            wildcard = string_enum_component_type.matching_type.wildcard_char
        except Exception as e:
            print(f"Warning -- did not find the `wildcard_char` on the matching_type; defaulting to '*'. Details: {e}")
            wildcard = "*"

        if value == wildcard:
            return z_all_vals_re_ref
        # we allow the use of variables in string enums
        if TEMPLATE_LEFT_DL in value:
            return self._check_string_part_for_var_template(value)
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
        """
        Converts a `value` for a `string_component_type` to a z3 expression, handling the character set
        and wildcard character associated with the `string_component_type`. 
        Additionally, if the SUPPORT_TEMPLATE_VARIABLES constant is set to true, this function will 
        replace instances of variables occurring in `value` with a z3.Re(free_variable) expression.

        The z3 expression returned is built on z3 regular expressions.
        """
        charset = string_component_type.char_set
        try:
            wildcard = string_component_type.matching_type.wildcard_char
        except:
            print("Warning -- did not find the `wildcard_char` on the matching_type; defaulting to '*'.")
            wildcard = "*"
        if not wildcard:
            raise NotImplementedError(f"Got none for wildcard for: {string_component_type.name}; wildcard must be specified.")
        
        # create a z3 ReRef that matches any character from the charset
        z_all_vals_re_ref = z3.Star(z3.Union([z3.Re(z3.StringVal(c)) for c in charset]))
        if SUPPORT_TEMPLATE_VARIABLES:                
            # check that the value is contained within the charset plus the * character and the delimiters
            additional_allowed_chars = wildcard + TEMPLATE_LEFT_DL + TEMPLATE_RIGHT_DL + " "
            if not charset.union(set(additional_allowed_chars)).intersection(set(value)) == set(value):
                raise Exception(f"Data must be contained within the charset for this StringComponent ({string_component_type.name}).")
        else:
            # check that the value is contained within the charset plus the * character
            if not charset.union(set(wildcard)).intersection(set(value)) == set(value):
                raise Exception(f"Data must be contained within the charset for this StringComponent ({string_component_type.name}).")

        # if the value is just a single wildcard character, then the expression for the value is the z3 ReRef for 
        # the entire charset
        if value == wildcard:
            return z_all_vals_re_ref
        
        # otherwise, if there are no wildcards in the value at all, then the z3 expression for the value is just the 
        # string literal, with possibly some variable templates.
        if not wildcard in value:
            if SUPPORT_TEMPLATE_VARIABLES:
                return self._check_string_part_for_var_template(value)
            else:
                return z3.Re(z3.StringVal(value))
        
        # otherwise, if we are here, then the value contains the wild card character plus other characters.
        # we begin by splitting the value into parts based on the wild chard character 
        parts = value.split('*')

        # compute the first one since Concat requires at least two args.
        # if we are supporting template variables, then we need to convert parts[0] to a 
        if SUPPORT_TEMPLATE_VARIABLES:
            result = z3.Concat(self._check_string_part_for_var_template(parts[0]), z_all_vals_re_ref)
        else:
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
                if SUPPORT_TEMPLATE_VARIABLES:
                    return z3.Concat(result, self._check_string_part_for_var_template(part))
                else:
                    return z3.Concat(result, z3.Re(z3.StringVal(part)))
            if SUPPORT_TEMPLATE_VARIABLES:
                result = z3.Concat(result, self._check_string_part_for_var_template(part))
            else:
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
        """

        *** This method is not used and deprecated. ***

        This implementation is the most similar to the string and enum implementations where it returns a single 
        boolean encoding. This implementation has the problem that fields within the tuple get smashed together which
        can lead to false equivalences; for ex, p1 = (a2, cpsjstubbs) equals p2= (a2cps, jstubbs) in this impl.
        """
        expr = self._encode_tuple_parts(tuple_component_type, value)
        return self._create_bool_encoding(tuple_component_type.name, expr)


    def _encode_tuple_list(self, tuple_component_type, value):
        """
        This implementation returns a list of boolean encodings, an encoding for each field in the list. The encoding
        is over a free variable with name = {tuple_name}_{field_name}.
        """
        res = []
        for idx, field in enumerate(tuple_component_type.fields):
            val = value[idx]
            # check the type of each field and call the appropriate _encode method...
            # StringComponents have a `char_set` and `max_len`
            if hasattr(field, "char_set") and hasattr(field, "max_len"):
                result = self._get_string_expr(field, val)
            # Enums have a `values` field
            elif hasattr(field, "values"):
                result = self._get_string_enum_expr(field, val)
            res.append(self._create_bool_encoding(f'{tuple_component_type.name}_{field.name}', result))
        return res


    def encode_policy_set(self, P):
        """
        Encode a policy set, P. 
        Returns a list of z3 expressions (one for each policy in the set, P) representing the constraints specified
        by each component of the policy.
        """
        final_result = []
        for p in P:
            component_encodings = []
            # every policy has a `components` attribute which contains components of the different types (enum, string, tuple)
            # as well as the decision component. 
            for component in self.policy_type.components:
                # The names of the attributes on the `components` object on the policy are the same as the names on the policy_type
                # object.
                policy_comp = getattr(p.components, component.name)
                # the decision component is special: we don't need to encode anything from the decision component, we just need to
                # set the is_allow_policy boolean based on it.
                if policy_comp.name == 'decision':
                    continue

                # Below, we determine the method to use for encoding based on the existence of fields we know are 
                # uniquely required for each type. This "duck typing" approach should be revisited, as it could be brittle if
                # new types are added. 
                # 
                # tuples are the only type to have a `fields` attribute
                if hasattr(policy_comp, 'fields'):
                    component_encodings.extend(self._encode_tuple_list(policy_comp, policy_comp.data))
                # string_enums are the only type to have a `values` attribute
                elif hasattr(component, 'values'):
                    component_encodings.append(self._encode_string_enum(policy_comp, policy_comp.data))
                # strings are the only type to have a `max_len` attribute
                elif hasattr(policy_comp, 'max_len') and hasattr(policy_comp, 'char_set'):
                    component_encodings.append(self._encode_string(policy_comp, policy_comp.data))
            final_result.append(z3.And(*component_encodings))
        return final_result

    
    def combine_allow_deny_set_encodings(self, allow_match_list, deny_match_list):
        if len(deny_match_list) == 0:
            return z3.Or(*allow_match_list)
        else:
            if len(allow_match_list) == 0:
                return z3.Not(z3.Or(*deny_match_list))

            return z3.And(z3.Or(*allow_match_list), z3.Not(z3.Or(*deny_match_list)))


    def encode(self):
        """
        Encode all policies in the two policy sets.
        """
        # For each policy set, p and q, we divide the policies into "allow" and "deny" sets.
        self.p_allow_set = [p for p in self.policy_set_p if p.components.decision.data == 'allow']
        self.p_allow_match_list = self.encode_policy_set(self.p_allow_set)

        self.p_deny_set = [p for p in self.policy_set_p if p.components.decision.data == 'deny']
        self.p_deny_match_list = self.encode_policy_set(self.p_deny_set)
        self.P = self.combine_allow_deny_set_encodings(self.p_allow_match_list, self.p_deny_match_list)

        self.q_allow_set = [q for q in self.policy_set_q if q.components.decision.data == 'allow']
        self.q_allow_match_list = self.encode_policy_set(self.q_allow_set)
        
        self.q_deny_set = [q for q in self.policy_set_q if q.components.decision.data == 'deny']
        self.q_deny_match_list = self.encode_policy_set(self.q_deny_set)
        self.Q = self.combine_allow_deny_set_encodings(self.q_allow_match_list, self.q_deny_match_list)


    def prove(self, statement_1, statement_2) -> ImplResult:
        """
        Determine whether statement_1 => statement_2. 
        cf., https://github.com/Z3Prover/z3/blob/master/src/api/python/z3/z3.py#L9069
        """
        solver = z3.Solver()
        # We add the negation of the statement we are trying to prove and check if it is unsatisfiable, 
        # meaning that the original implication is true
        solver.add(z3.Not(z3.Implies(statement_1, statement_2)))
        #print(solver.sexpr())
        result = solver.check()
        # whether we were able to prove the statement. There are 3 possibilities:
        #  a) we are able to prove the statement
        #  b) we were able find a counterexample, disproving the statement
        #  c) we were not able to prove the statement but we were not able to find a counter example either
        proved = False
        found_counter_ex = True
        model = None
        if result == z3.unsat:
            proved = True
            found_counter_ex = False
        elif result == z3.unknown:
            found_counter_ex = False
            #model = solver.model()
        else:
            # in this case we did not prove the statement but in fact found a counter example.
            model = solver.model()
            
        impl_result = ImplResult(proved=proved, found_counter_ex=found_counter_ex, model=model)
        return impl_result


    def p_implies_q(self) -> ImplResult:
        return self.prove(self.P, self.Q)


    def q_implies_p(self) -> ImplResult:
        return self.prove(self.Q, self.P)
