from lib.finite_field import FFPoly, rand_ffpoly
import re

def rand_poly(degree: int) -> list:
    return Poly([rand_ffpoly(128) for i in range(degree+1)])

class Poly:
    # Polynomial is represented as a list of coefficients
    # [1, 2, 3] = 1 + 2x + 3x^2 = 3x^2 + 2x + 1
    def init_from_str(self, coeffs):
        coeffs = coeffs.replace(" X ", " X^1 ").replace("*", " ")

        # Step 1: Extract all coefficients using regex
        #       Example: (1) X^4 + (x + 1) X^3 + (x + 1) X^2
        #       Result:  ["1", "x + 1", "x + 1", "0, 1"]
        all_coeffs = re.findall(r"\((.*?)\)", coeffs)
        all_coeffs = [FFPoly(i) for i in all_coeffs]

        # Step 2: Get all exponents
        #       Example: (1) X^4 + (x + 1) X^3 + (1) X + (x^2 + 1)
        #       Result:  [4, 3, 1, 0]
        all_exponents = re.findall(r"X\^(\d+)", coeffs)
        all_exponents = [int(i) for i in all_exponents]

        # Step 3: Check if poly has zero exponent (ends with ')' or 'X')
        #       Example: (1) X^4 + (x + 1) X^3 + (1) X + (x^2 + 1)
        #       Result:  [4, 3, 1, 0]
        if coeffs.endswith(")") or coeffs.endswith("X"):
            all_exponents.append(0)

        # Step 4: Get highest exponent
        highest_exponent = max(all_exponents)

        # Step 5: Create list of coefficients
        out_coeffs = []
        for i in range(highest_exponent+1):
            if i in all_exponents:
                out_coeffs.append(all_coeffs[all_exponents.index(i)])
            else:
                out_coeffs.append(FFPoly(0))

        return out_coeffs

    def init_from_list(self, coeffs):
        # If coeffs is empty, create a zero polynomial
        if len(coeffs) == 0: return [FFPoly(0)]

        # All elements should be of type FFPoly
        if isinstance(coeffs[0], FFPoly):
            return [c for c in coeffs]
        else:
            return [FFPoly(c) for c in coeffs]

    def __init__(self, coeffs) -> None:
        self._coeffs = []
        if isinstance(coeffs, str):
            self._coeffs = self.init_from_str(coeffs)
        elif isinstance(coeffs, list):
            self._coeffs = self.init_from_list(coeffs)
        else:
            raise TypeError("Operand must be of type str or list")

        # Remove leading zeros
        self.strip()

    def strip(self) -> None:
        while self._coeffs and self._coeffs[-1] == 0 and len(self) > 1:
            self._coeffs.pop()

    @property
    def coeffs(self) -> list:
        return self._coeffs

    @property
    def inverse(self):
        return Poly([i.inverse for i in self.coeffs])

    @property
    def copy(self):
        return Poly([i.copy for i in self.coeffs])

    @property
    def degree(self) -> int:
        return len(self._coeffs) - 1

    @property
    def is_zero(self) -> bool:
        return self.degree == 0 and self._coeffs[0] == 0

    @property
    def is_gt_or_equal_one(self) -> bool:
        return self.degree > 0 or self._coeffs[0].poly >= 1

    def __len__(self):
        return len(self._coeffs)

    def __getitem__(self, idx):
        return self._coeffs[idx]

    def __setitem__(self, idx, val):
        if not isinstance(val, FFPoly):
            raise TypeError("Operand must be of type FFPoly")

        self._coeffs[idx] = val

    def __str__(self) -> str:
        out = ""
        for i in range(len(self._coeffs)-1, -1, -1):
            if self._coeffs[i] == 0: continue

            if i == 0:
                out += f"({self._coeffs[i]})"
            elif i == 1:
                out += f"({self._coeffs[i]}) X + "
            else:
                out += f"({self._coeffs[i]}) X^{i} + "

        if out.endswith(" + "): out = out[:-3]
        if out == "": out = "0"

        return out

    def __add__(self, other):
        if not isinstance(other, Poly):
            raise TypeError("Operand must be of type Poly")

        l_a= len(self._coeffs)
        l_b = len(other._coeffs)
        smaller = l_a < l_b and self._coeffs or other._coeffs
        larger = smaller == self._coeffs and other._coeffs or self._coeffs
        for i in range(len(smaller)):
            larger[i] += smaller[i]
        return Poly(larger)

    def __neg__(self):
        #return Poly([i.inverse for i in self._coeffs])
        raise NotImplementedError("Substraction is not implemented yet")

    def __sub__(self, other):
        max_len = max(len(self.coeffs), len(other.coeffs))
        a = self.coeffs + [FFPoly(0)] * (max_len - len(self.coeffs))
        b = other.coeffs + [FFPoly(0)] * (max_len - len(other.coeffs))
        result_coeffs = [a[i] - b[i] for i in range(max_len)]
        return Poly(result_coeffs)

    def __mul__(self, other):
        if not isinstance(other, Poly):
            raise TypeError("Operand must be of type Poly")

        l_a= len(self._coeffs)
        l_b = len(other._coeffs)

        # preallocate list
        res = [FFPoly(0)]*(l_a + l_b - 1)

        # "HäNdE sChÜtTeLn" :)
        for a_pow, a_coeff in enumerate(self._coeffs):
            for b_pow, b_coeff in enumerate(other._coeffs):
                res[a_pow + b_pow] += a_coeff * b_coeff

        return Poly(res)

    def __eq__(self, other):
        if not isinstance(other, Poly):
            raise TypeError("Operand must be of type Poly")

        if len(self._coeffs) != len(other._coeffs):
            return False

        for i in range(len(self._coeffs)):
            if self._coeffs[i] == other._coeffs[i]: continue
            return False

        return True

    def __lt_(self, other):
        if not isinstance(other, Poly):
            raise TypeError("Operand must be of type Poly")

        if len(self._coeffs) < len(other._coeffs):
            return True
        elif len(self._coeffs) > len(other._coeffs):
            return False
        else:
            for i in range(len(self._coeffs)-1, -1, -1):
                if self._coeffs[i] < other._coeffs[i]:
                    return True
                elif self._coeffs[i] > other._coeffs[i]:
                    return False
            return False

    def __gt__(self, other):
        if not isinstance(other, Poly):
            raise TypeError("Operand must be of type Poly")

        if len(self._coeffs) > len(other._coeffs):
            return True
        elif len(self._coeffs) < len(other._coeffs):
            return False
        else:
            for i in range(len(self._coeffs)-1, -1, -1):
                if self._coeffs[i] > other._coeffs[i]:
                    return True
                elif self._coeffs[i] < other._coeffs[i]:
                    return False
            return False

    def __le__(self, other):
        return self < other or self == other

    def __ge__(self, other):
        return self > other or self == other

    def __mod__(self, other):
        if other.degree < 0:
            raise ZeroDivisionError("Modulo by zero polynomial")
        dividend = self.copy
        divisor_degree = other.degree
        divisor_leading_coeff = other._coeffs[-1]
        first_round = True
        while dividend >= other or first_round:
            degree_diff = dividend.degree - divisor_degree
            leading_coeff = dividend._coeffs[-1] / divisor_leading_coeff
            term = [FFPoly(0)] * degree_diff + [leading_coeff]

            dividend -= Poly(term) * other
            first_round = False

        return dividend

    def __truediv__(self, other):
        if isinstance(other, Poly):
            if other.degree < 0:
                raise ZeroDivisionError("Division by zero polynomial")

            if self == other:
                return Poly([1])

            dividend = self.copy
            divisor_degree = other.degree
            divisor_leading_coeff = other._coeffs[-1]
            quotient_coeffs = [FFPoly(0)] * (dividend.degree - divisor_degree + 1)

            while dividend.degree >= other.degree:
                degree_diff = dividend.degree - divisor_degree
                leading_coeff = dividend._coeffs[-1] / divisor_leading_coeff
                quotient_coeffs[degree_diff] = leading_coeff

                term = [FFPoly(0)] * degree_diff + [leading_coeff]

                dividend -= Poly(term) * other

            return Poly(quotient_coeffs)
        elif isinstance(other, FFPoly):
            return Poly([i * other.inverse for i in self.coeffs])
        else:
            raise TypeError("Operand must be of type Poly or FFPoly")

    def __floordiv__(self, other):
        return self / other

    def __pow__(self, exp):
        if not isinstance(exp, int):
            raise TypeError("Operand must be of type int")
        if exp == 0: return Poly([1])
        elif exp == 1: return self.copy
        else:
            if exp % 2 == 0:
                step = self ** (exp // 2)
                return step * step
            else:
                step = self ** (exp // 2)
                return step * step * self

    def square_and_multiply(self, exp: int, mod):
        if not isinstance(mod, Poly):
            raise TypeError("Operand must be of type Poly")

        if exp == 0:
            return Poly([1])
        elif exp == 1:
            return self
        else:
            if exp % 2 == 0:
                step = self.square_and_multiply(exp // 2, mod)
                return (step * step) % mod
            else:
                step = self.square_and_multiply(exp // 2, mod)
                return (step * step * self) % mod

    def gcd(self, b):
        if not isinstance(b, Poly):
            raise TypeError("Operand must be of type Poly")

        a = self.copy
        while b != Poly([0]):
            a, b = b, a % b

        # Make monical
        a = a / a[-1]

        return a

    def solve(self, exponent: list):
        # Return a FFPoly by inserting the exponent into the polynomial
        assert len(exponent) == len(self.coeffs), "Invalid exponent length: Expected %d, got %d" % (len(self.coeffs), len(exponent))

        solution = FFPoly(0)
        for degree, coeff in enumerate(self.coeffs):
            solution += coeff * (exponent[degree] ** degree)

        return solution
