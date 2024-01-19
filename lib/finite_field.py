import random

def block_to_poly(block: bytes) -> int:
    # convert to int
    block = int.from_bytes(block, "big")
    # reverse bits
    return int(format(block, '0128b')[::-1], 2)

def block_to_exponents(block: bytes) -> list:
    poly = block_to_poly(block)

    exponents = []
    for i in range(poly.bit_length()):
        if poly & (1<<i):
            exponents.append(i)
    return exponents

def poly_to_block(poly: int) -> bytes:
    bin_poly = ""
    for i in range(128):
        if poly & (1<<i):
            bin_poly += "1"
        else:
            bin_poly += "0"
    return int(bin_poly, 2).to_bytes(16, "big")

def exponents_to_poly(exponents: list) -> int:
    poly = 0
    for e in exponents:
        poly |= (1<<e)
    return poly

def exponents_to_block(exponents: list) -> bytes:
    poly = exponents_to_poly(exponents)
    return poly_to_block(poly)

def str_to_block(string: str) -> bytes:
    raise NotImplementedError("str_to_block not yet implemented")
    string = "Y" + string + "X"
    str = string.replace(" ", "").replace("x^", "").replace("+1X", "+0X").replace("Y1X", "Y0X").replace("+x", "+1").replace("x", "1")
    str = str.replace("X", "")
    str = str.replace("Y", "")
    return exponents_to_poly([int(i) for i in str.split("+")])

def str_to_poly(string: str):
    raise NotImplementedError("str_to_poly not yet implemented")
    string = "Y" + string + "X"
    str = string.replace(" ", "").replace("x^", "").replace("+1X", "+0X").replace("Y1X", "Y0X").replace("+x", "+1").replace("x", "1")
    str = str.replace("X", "")
    str = str.replace("Y", "")
    return exponents_to_poly([int(i) for i in str.split("+")])

def rand_ffpoly(degree: int):
    return FFPoly(random.randint(0, (1<<degree)-1))

class FFPoly:
    def __init__(self, block):
        self._field = (1<<128)|(1<<7)|(1<<2)|(1<<1)|(1<<0)
        if isinstance(block, bytes):
            self._block = block
            self._poly = block_to_poly(block)
        elif isinstance(block, int):
            # calculate just-in-time for performance
            self._block = None
            self._poly = block
        elif isinstance(block, FFPoly):
            assert block.field == self.field, "Fields do not match"
            self._block = block.block
            self._poly = block.poly
        elif isinstance(block, str):
            self._block = str_to_block(block)
            self._poly = str_to_poly(block)
        else:
            raise TypeError(f"Invalid type for FFPoly: {type(block)}")

        if self._poly > self._field:
            self.reduce()
            self._block = poly_to_block(self._poly)

    def reduce(self):
        mod = self._field
        shift = self._poly.bit_length() - mod.bit_length()
        while shift >= 0:
            self._poly ^= mod << shift
            shift = self._poly.bit_length() - mod.bit_length()

    @property
    def poly(self):
        return self._poly

    @property
    def block(self):
        if self._block is None:
            self._block = poly_to_block(self._poly)
        return self._block

    @property
    def field(self):
        return self._field

    @property
    def exponents(self):
        return block_to_exponents(self.block)

    @property
    def degree(self):
        return self._poly.bit_length() - 1

    @property
    def order(self):
        return 2**128

    @property
    def copy(self):
        return FFPoly(self._poly)

    @property
    def inverse(self):
        exponent = 2 ** 128 - 2
        return FFPoly(self ** exponent)

    # combined multiplication and modular reduction
    def __mul__(self, other):
        b = other.poly
        if b == 1: return self

        a = self.poly
        #if a == 1: return other

        m = self.field

        # Performance optimization
        if a == 0 or b == 0: return FFPoly(0)

        # Pre-compute a ^= m if a is consistently larger than m
        if a > m: a ^= m

        c = 0
        m_bit_length = m.bit_length()
        while b > 0:
            if b & 1: c ^= a
            b >>= 1
            a <<= 1
            if a.bit_length() >= m_bit_length: a ^= m
        return FFPoly(c)

    # square and multiply algorithm
    def __pow__(self, power):
        res = FFPoly(1)
        base = FFPoly(self.poly)
        while power > 0:
            if power & 1:
                res *= base
            base *= base
            if base == 1: break
            power >>= 1
        return res

    def __floordiv__(self, other):
        if other == 0:
            raise ZeroDivisionError("Cannot divide by zero")
        # TODO: optimize
        return self * other.inverse

    def __truediv__(self, other):
        return self // other

    def __xor__(self, other):
        return FFPoly(self.poly ^ other.poly)

    def __add__(self, other):
        return FFPoly(self.poly ^ other.poly)

    def __neg__(self):
        return FFPoly(0) - self

    def __sub__(self, other):
        return FFPoly(self.poly ^ other.poly)

    def __eq__(self, other) -> bool:
        if isinstance(other, int):
            return self.poly == other
        else:
            return self.poly == other.poly

    def __lt__(self, other) -> bool:
        if isinstance(other, int):
            return self.poly < other
        else:
            return self.poly < other.poly

    def __gt__(self, other) -> bool:
        if isinstance(other, int):
            return self.poly > other
        else:
            return self.poly > other.poly

    def __mod__(self, other):
        if self._poly < other.poly:
            return FFPoly(self)

        res = self.copy
        shift = self._poly.bit_length() - other.poly.bit_length()
        while shift >= 0:
            res._poly ^= other.poly << shift
            shift = res._poly.bit_length() - other.poly.bit_length()
        return FFPoly(res)

    def __str__(self) -> str:
        formatted = ""
        if self._poly == 0: return "0"
        for i in range(self._poly.bit_length()):
            if self._poly & (1<<i):
                formatted = f"x^{i} + " + formatted
        # Cosmetic changes to the string
        formatted = formatted.replace("x^1 ", "x ").replace("x^0", "1")
        return formatted[:-3]
