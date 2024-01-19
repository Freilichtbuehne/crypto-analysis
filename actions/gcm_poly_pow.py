from lib.polynomial import Poly

import base64

def load(json_object):
    assert "base" in json_object, "Missing JSON value 'base'"
    assert "exponent" in json_object, "Missing JSON value 'exponent'"

    base = [base64.b64decode(i) for i in json_object["base"]]; base = Poly(base)
    exponent = json_object["exponent"]

    coeffs = (base ** exponent).coeffs

    encoded = [base64.b64encode(i.block).decode('utf-8') for i in coeffs]

    output_JSON_object = {
        "result": encoded
    }
    return output_JSON_object
