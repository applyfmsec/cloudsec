"""
A cloudsec backend based on the cvc5 SMT solver.
"""

import cvc5
from cvc5 import Kind, Term, Solver
from cloudsec.backends import CloudsecBackend, ImplResult


class CVC5Backend(CloudsecBackend):

    def __init__(self, policy_type, policy_set_p, policy_set_q)-> None:
        self.free_variables = []
        self.policy_type = policy_type
        self.policy_set_p = policy_set_p
        self.policy_set_q = policy_set_q
        self.slv = cvc5.Solver()
        # Set the logic
        self.slv.setLogic("ALL")
        # Produce models
        self.slv.setOption("produce-models", "true")
        # The option strings-exp is needed
        self.slv.setOption("strings-exp", "true")
        # Set output language to SMTLIB2
        self.slv.setOption("output-language", "smt2")
        self.slv.setOption("produce-unsat-cores", "true")
        self.string = self.slv.getStringSort()


    def _create_bool_encoding(self, name, expr:Term)-> cvc5.Term:
        """
        Create a cvc5 boolean encoding of the expression, `expr`.
        using the free variable free_var (i.e., the name of the component).
        This should be the last method called when encoding a component.
        """
        free_var = self._check_and_create_free_variable(name)
        term = self.slv.mkTerm(Kind.STRING_IN_REGEXP, free_var, expr)
        return term

    def _get_string_enum_expr(self, string_enum_component_type, value):
        values = string_enum_component_type.values
        p = [self.slv.mkTerm(Kind.STRING_TO_REGEXP, self.slv.mkString(v)) for v in values]
        z_all_vals_re_ref = self.slv.mkTerm(Kind.REGEXP_UNION, *p)
        # todo -- at this point in time, we do not distinguish the different matching types, but
        #         we will in a future release.
        try:
            wildcard = string_enum_component_type.matching_type.wildcard_char
        except Exception as e:
            print(f"Warning -- did not find the `wildcard_char` on the matching_type; defaulting to '*'. Details: {e}")
            wildcard = "*"

        if value == wildcard:
            return z_all_vals_re_ref
        if value not in values:
            message = f"value {value} is not allowed for enum type {string_enum_component_type.name}; allowed values are {values}"
            raise Exception(message)
        term = self.slv.mkTerm(Kind.STRING_TO_REGEXP, self.slv.mkString(value))
        return term

    def _encode_string_enum(self, string_enum_component_type, value):
        """
        Encodes a StringEnumComponent type into a cvc5 boolean expression.

        string_component_type: An instance of StringEnumComponent
        value: the data associated with the policy for this component.

        """
        expr = self._get_string_enum_expr(string_enum_component_type, value)
        return self._create_bool_encoding(string_enum_component_type.name, expr)

    def _get_string_expr(self, string_component_type, value):
        charset = string_component_type.char_set
        try:
            wildcard = string_component_type.matching_type.wildcard_char
        except:
            print("Warning -- did not find the `wildcard_char` on the matching_type; defaulting to '*'.")
            wildcard = "*"
        # create

        p = [self.slv.mkTerm(Kind.STRING_TO_REGEXP, self.slv.mkString(c)) for c in charset]
        z_all_vals_re_ref = self.slv.mkTerm(Kind.REGEXP_STAR, self.slv.mkTerm(Kind.REGEXP_UNION, *p))
        # check that the value is contained within the charset plus the * character
        if not charset.union(set('*')).intersection(set(value)) == set(value):
            raise Exception(
                f"Data must be contained within the charset for this StringComponent ({string_component_type.name}).")
        if value == wildcard:
            return z_all_vals_re_ref
        if not wildcard in value:
            return self.slv.mkTerm(Kind.STRING_TO_REGEXP, self.slv.mkString(value))
        parts = value.split('*')
        # compute the first one since Concat requires at least two args.
        result = self.slv.mkTerm(Kind.REGEXP_CONCAT,
                                 self.slv.mkTerm(Kind.STRING_TO_REGEXP,
                                                 self.slv.mkString(parts[0])),
                                 z_all_vals_re_ref)
        # handle the case of str containing a single * in the last char
        if len(parts) == 2 and value[-1] == wildcard:
            return result
        for idx, part in enumerate(parts[1:]):
            # it is possible the str ends in a '*', in which case we only need to add a single re_all_chars,
            # unless we already did because this is the
            if part == '':
                if idx == 0:
                    return result

                return self.slv.mkTerm(Kind.REGEXP_CONCAT, result, z_all_vals_re_ref)
            # handle whether this is the final part or not:
            if idx + 2 == len(parts):
                return self.slv.mkTerm(Kind.REGEXP_CONCAT,result, self.slv.mkTerm(Kind.STRING_TO_REGEXP,
                               self.slv.mkString(part)))
            result = self.slv.mkTerm(Kind.REGEXP_CONCAT, result, self.slv.mkTerm(Kind.STRING_TO_REGEXP,
                                                                                 self.slv.mkString(part)))
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

        term = self.slv.mkTerm(Kind.REGEXP_CONCAT, *res)
        return term

    def _encode_tuple(self, tuple_component_type, value):
        """
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
            # StringComponents have a char_set and mex_len
            if hasattr(field, "char_set") and hasattr(field, "max_len"):
                result = self._get_string_expr(field, val)
            elif hasattr(field, "values"):
                result = self._get_string_enum_expr(field, val)
            res.append(self._create_bool_encoding(f'{tuple_component_type.name}_{field.name}', result))

        return res

    def encode_policy_set(self, P):
        """
        Encode a policy set, P.
        """
        final_result = []
        for p in P:
            component_encodings = []
            # every policy has a `components` attribute which contains componenets of the different types (enum, string, tuple)
            # as well as the decision component.
            for component in self.policy_type.components:
                # The names of the attributes on the `components` object on the policy are the same as the names on the policy_type
                # object.
                policy_comp = getattr(p.components, component.name)
                # the decision component is special: we don't need to encode anything from the decision component, we just need to
                # set the is_allow_policy boolean based on it.
                if policy_comp.name == 'decision':
                    continue

                # tuples have a `fields` attribute
                if hasattr(policy_comp, 'fields'):
                    component_encodings.extend(self._encode_tuple_list(policy_comp, policy_comp.data))
                elif hasattr(component, 'values'):
                    component_encodings.append(self._encode_string_enum(policy_comp, policy_comp.data))
                elif hasattr(policy_comp, 'max_len') and hasattr(policy_comp, 'char_set'):
                    component_encodings.append(self._encode_string(policy_comp, policy_comp.data))

            if len(component_encodings) == 1:
                final_result.append(component_encodings[0])
            else:
                final_result.append(self.slv.mkTerm(Kind.AND, *component_encodings))

        return final_result

    def _check_and_create_free_variable(self, free_var_name):
        if len(self.free_variables) == 0:
            free_var = self.slv.mkConst(self.string, free_var_name)
            self.free_variables.append(free_var)

        flag = False

        for v in self.free_variables:
            if free_var_name == v.getSymbol():
                free_var = v
                flag = True
                break
        if flag == False:
            free_var = self.slv.mkConst(self.string, free_var_name)
            self.free_variables.append(free_var)
        return free_var

    def combine_allow_deny_set_encodings(self, allow_match_list, deny_match_list):

        if len(allow_match_list) == 0:
            if len(deny_match_list) == 1:
                return self.slv.mkTerm(Kind.NOT, deny_match_list[0])
            else:
                return self.slv.mkTerm(Kind.NOT, self.slv.mkTerm(Kind.OR,*deny_match_list))

        if len(allow_match_list) == 1:
            allow_or_term = allow_match_list[0]
        else:
            allow_or_term = self.slv.mkTerm(Kind.OR, *allow_match_list)


        if len(deny_match_list) == 0:
           return allow_or_term
        else:
            if len(deny_match_list) == 1:
                return self.slv.mkTerm(Kind.AND,
                    allow_or_term,
                    self.slv.mkTerm(Kind.NOT, deny_match_list[0]))
            else:
                return self.slv.mkTerm(Kind.AND,
                                        allow_or_term,
                                           self.slv.mkTerm(Kind.NOT,
                                                      self.slv.mkTerm(Kind.OR,*deny_match_list)))
    def encode(self):
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
        # print("free variables list:", self.free_variables)
        stmt = self.slv.mkTerm(Kind.NOT, self.slv.mkTerm(Kind.IMPLIES, statement_1, statement_2))
        # print("\n statement:= ", stmt, "\n")
        result = self.slv.checkSatAssuming(stmt)
        proved = False
        found_counter_ex = True
        model = []
        if result.isUnsat():
            proved = True
            found_counter_ex = False
        elif result.isSat():
            for fvar in self.free_variables:
                model.append((fvar.getSymbol(),self.slv.getValue(fvar)))
        else:
            #print(" ------ Unknown  ----- ")
            found_counter_ex = False
            for fvar in self.free_variables:
                print("\n", fvar.getSymbol(), "= ", self.slv.getValue(fvar))
                model.append((fvar.getSymbol(), self.slv.getValue(fvar)))

        impl_result = ImplResult(proved=proved, found_counter_ex=found_counter_ex, model=model)
        return impl_result


    def p_implies_q(self) -> ImplResult:
        print("\n Prove p => q ")
        result = self.prove(self.P, self.Q)
        print("\n Summary: p => q result: \n")
        print("proved: ", result.proved)
        if not result.proved :
            print("found counter example: ", result.found_counter_ex)
            if result.found_counter_ex:
                print("counter-example : ", result.model)
        return result

    def q_implies_p(self) -> ImplResult:
        print("\n Prove q => p : ")
        result = self.prove(self.Q, self.P)
        print("\n Summary: q => p result: \n")
        print("proved: ", result.proved)
        if not result.proved:
            print("found counter example: ", result.found_counter_ex)
            if result.found_counter_ex:
                print("counter-example : ", result.model)
        return result
