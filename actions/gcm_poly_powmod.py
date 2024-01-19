from lib.polynomial import Poly

import base64

def load(json_object):
    assert "base" in json_object, "Missing JSON value 'base'"
    assert "modulo" in json_object, "Missing JSON value 'modulo'"
    assert "exponent" in json_object, "Missing JSON value 'exponent'"

    base = [base64.b64decode(i) for i in json_object["base"]]; base = Poly(base)
    modulo = [base64.b64decode(i) for i in json_object["modulo"]]; modulo = Poly(modulo)
    exponent = json_object["exponent"]

    a_pow_b = base.square_and_multiply(exponent, modulo)

    encoded = []
    if a_pow_b.is_gt_or_equal_one:
        encoded = [base64.b64encode(i.block).decode('utf-8') for i in a_pow_b.coeffs]

    output_JSON_object = {
        "result": encoded
    }
    return output_JSON_object
