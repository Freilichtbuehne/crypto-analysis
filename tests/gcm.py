from lib.finite_field import FFPoly, rand_ffpoly
from lib.test_helper import test_kauma_output, test_kauma_output_raw

from sage.all import *

import unittest, json

class TestGCM(unittest.TestCase):

    def test_task_block2poly(self):
        json_path = "tests/test_gcm_block2poly.json"
        test_kauma_output(self, "block2poly", json_path, ["exponents"])

    def test_task_poly2block(self):
        json_path = "tests/test_gcm_poly2block.json"
        test_kauma_output(self, "poly2block", json_path, ["block"])

    def test_task_clmul(self):
        json_path = "tests/test_gcm_clmul.json"
        json_object = None
        with open(json_path, "r") as json_file:
            json_object = json.load(json_file)

        for case in json_object:
            inp = json.dumps(case, indent=2)
            output = json.dumps({"a_times_b": case["a_times_b"]}, indent=2)
            test_kauma_output_raw(self, "clmul", inp, output)

    def test_task_encrypt(self):
        json_path = "tests/test_gcm_encrypt.json"
        json_object = None
        with open(json_path, "r") as json_file:
            json_object = json.load(json_file)

        for case in json_object:
            inp = json.dumps(case["tc"], indent=2)
            output = json.dumps(case["expected_result"], indent=2)
            test_kauma_output_raw(self, "encrypt", inp, output)

    def test_task_polyadd(self):
        json_path = "tests/test_gcm_polyadd.json"
        json_object = None
        with open(json_path, "r") as json_file:
            json_object = json.load(json_file)

        for case in json_object:
            inp = json.dumps(case, indent=2)
            output = json.dumps({"result": case["result"]}, indent=2)
            test_kauma_output_raw(self, "polyadd", inp, output)

    def test_task_polydiv(self):
        json_path = "tests/test_gcm_polydiv.json"
        json_object = None
        with open(json_path, "r") as json_file:
            json_object = json.load(json_file)

        for case in json_object:
            inp = json.dumps(case, indent=2)
            output = json.dumps({"result": case["result"]}, indent=2)
            test_kauma_output_raw(self, "polydiv", inp, output)

    def test_task_polypow(self):
        json_path = "tests/test_gcm_polypow.json"
        test_kauma_output(self, "polypow", json_path, ["result"])

    def test_task_polypowmod(self):
        json_path = "tests/test_gcm_polypowmod.json"
        json_object = None
        with open(json_path, "r") as json_file:
            json_object = json.load(json_file)

        for case in json_object:
            inp = json.dumps(case, indent=2)
            output = json.dumps({"result": case["result"]}, indent=2)
            test_kauma_output_raw(self, "polypowmod", inp, output)

    def test_task_recover(self):
        json_path = "tests/test_gcm_recover.json"
        test_kauma_output(self, "recover", json_path, ["msg4_tag"])

    def test_cz(self):
        json_path = "tests/test_gcm_cz.json"
        json_object = None
        with open(json_path, "r") as json_file:
            json_object = json.load(json_file)

        for case in json_object:
            inp = json.dumps(case["tc"], indent=2)
            output = json.dumps(case["expected_result"], indent=2)
            test_kauma_output_raw(self, "cz", inp, output)

    def test_arithmetic_mul(self):
        # Initialize SageMath
        F = GF(2)['a']; (a,) = F._first_ngens(1)
        K = GF(2**128, name='x', modulus=a**128 + a**7 + a**2 + a + 1 , names=('x',)); (x,) = K._first_ngens(1)

        rand_a = rand_ffpoly(128)
        rand_b = rand_ffpoly(128)

        # Test multiplication
        a_times_b = rand_a * rand_b
        a_times_b_sage = K(str(rand_a)) * K(str(rand_b))

        # Test random multiplication
        self.assertEqual(
            str(a_times_b),
            str(a_times_b_sage),
            "SageMath and Python implementation of finite field arithmetic mismatch: multiplication."
        )

        # Test multiplication with zero
        zero = FFPoly(0)
        a_times_zero = rand_a * zero
        a_times_zero_sage = K(str(rand_a)) * K(str(zero))

        self.assertEqual(
            str(a_times_zero),
            str(a_times_zero_sage),
            "SageMath and Python implementation of finite field arithmetic mismatch: multiplication with zero."
        )

    def test_arithmetic_add(self):
        # Initialize SageMath
        F = GF(2)['a']; (a,) = F._first_ngens(1)
        K = GF(2**128, name='x', modulus=a**128 + a**7 + a**2 + a + 1 , names=('x',)); (x,) = K._first_ngens(1)

        rand_a = rand_ffpoly(128)
        rand_b = rand_ffpoly(128)

        # Test addition
        a_plus_b = rand_a + rand_b
        a_plus_b_sage = K(str(rand_a)) + K(str(rand_b))

        # Test random addition
        self.assertEqual(
            str(a_plus_b),
            str(a_plus_b_sage),
            "SageMath and Python implementation of finite field arithmetic mismatch: addition."
        )

        # Test addition with zero
        zero = FFPoly(0)
        a_plus_zero = rand_a + zero
        a_plus_zero_sage = K(str(rand_a)) + K(str(zero))

        self.assertEqual(
            str(a_plus_zero),
            str(a_plus_zero_sage),
            "SageMath and Python implementation of finite field arithmetic mismatch: addition with zero."
        )

    def test_arithmetic_sub(self):
        # Initialize SageMath
        F = GF(2)['a']; (a,) = F._first_ngens(1)
        K = GF(2**128, name='x', modulus=a**128 + a**7 + a**2 + a + 1 , names=('x',)); (x,) = K._first_ngens(1)

        rand_a = rand_ffpoly(128)
        rand_b = rand_ffpoly(128)

        # Test subtraction
        a_minus_b = rand_a - rand_b
        a_minus_b_sage = K(str(rand_a)) - K(str(rand_b))

        # Test random subtraction
        self.assertEqual(
            str(a_minus_b),
            str(a_minus_b_sage),
            "SageMath and Python implementation of finite field arithmetic mismatch: subtraction."
        )

        # Test subtraction with zero
        zero = FFPoly(0)
        a_minus_zero = rand_a - zero
        a_minus_zero_sage = K(str(rand_a)) - K(str(zero))

        self.assertEqual(
            str(a_minus_zero),
            str(a_minus_zero_sage),
            "SageMath and Python implementation of finite field arithmetic mismatch: subtraction with zero."
        )

        # Test subtraction zero with zero
        zero = FFPoly(0)
        zero_minus_zero = zero - zero
        zero_minus_zero_sage = K(str(zero)) - K(str(zero))

        self.assertEqual(
            str(zero_minus_zero),
            str(zero_minus_zero_sage),
            "SageMath and Python implementation of finite field arithmetic mismatch: subtraction zero with zero."
        )

    def test_arithmetic_exp(self):
        # Initialize SageMath
        F = GF(2)['a']; (a,) = F._first_ngens(1)
        K = GF(2**128, name='x', modulus=a**128 + a**7 + a**2 + a + 1 , names=('x',)); (x,) = K._first_ngens(1)

        rand_a = rand_ffpoly(128)
        rand_b = rand_ffpoly(128)

        # Test exponentiation
        power = 2**128
        a_pow = rand_a ** power
        a_pow_sage = K(str(rand_a)) ** power

        # Test random exponentiation
        self.assertEqual(
            str(a_pow),
            str(a_pow_sage),
            "SageMath and Python implementation of finite field arithmetic mismatch: exponentiation."
        )

        # Test exponentiation with zero
        zero = FFPoly(0)
        zero_pow = zero ** power
        zero_pow_sage = K(str(zero)) ** power

        self.assertEqual(
            str(zero_pow),
            str(zero_pow_sage),
            "SageMath and Python implementation of finite field arithmetic mismatch: exponentiation with zero."
        )

    def test_arithmetic_div(self):
        # Initialize SageMath
        F = GF(2)['a']; (a,) = F._first_ngens(1)
        K = GF(2**128, name='x', modulus=a**128 + a**7 + a**2 + a + 1 , names=('x',)); (x,) = K._first_ngens(1)

        rand_a = rand_ffpoly(128)
        rand_b = rand_ffpoly(128)

        # Test division
        a_div_b = rand_a / rand_b
        a_div_b_sage = K(str(rand_a)) / K(str(rand_b))

        # Test random division
        self.assertEqual(
            str(a_div_b),
            str(a_div_b_sage),
            "SageMath and Python implementation of finite field arithmetic mismatch: division."
        )

        # Test division by one (assert no change)
        one = FFPoly(1)
        one_div = rand_a / one

        self.assertEqual(
            str(one_div),
            str(rand_a),
            "Assert no change when dividing by one."
        )


        # Test division with zero (assertion error)
        zero = FFPoly(0)
        with self.assertRaises(ZeroDivisionError):
            zero_div = rand_a / zero

    def test_arithmetic_pow(self):
        # Initialize SageMath
        F = GF(2)['a']; (a,) = F._first_ngens(1)
        K = GF(2**128, name='x', modulus=a**128 + a**7 + a**2 + a + 1 , names=('x',)); (x,) = K._first_ngens(1)

        rand_a = rand_ffpoly(128)
        rand_b = rand_ffpoly(128)

        # Test power
        power = 100
        a_pow = rand_a ** power
        a_pow_sage = K(str(rand_a)) ** power

        # Test random power
        self.assertEqual(
            str(a_pow),
            str(a_pow_sage),
            "SageMath and Python implementation of finite field arithmetic mismatch: power."
        )

        # Test power with zero
        zero = FFPoly(0)
        zero_pow = zero ** power
        zero_pow_sage = K(str(zero)) ** power

        self.assertEqual(
            str(zero_pow),
            str(zero_pow_sage),
            "SageMath and Python implementation of finite field arithmetic mismatch: power with zero."
        )
