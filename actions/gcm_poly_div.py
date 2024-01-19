from lib.polynomial import Poly

import base64

def load(json_object):
    assert "a" in json_object, "Missing JSON value 'a'"
    assert "b" in json_object, "Missing JSON value 'b'"

    a = [base64.b64decode(i) for i in json_object["a"]]; a = Poly(a)
    b = [base64.b64decode(i) for i in json_object["b"]]; b = Poly(b)

    a_div_b = a / b

    encoded = []
    if a_div_b.is_gt_or_equal_one:
        encoded = [base64.b64encode(i.block).decode('utf-8') for i in a_div_b.coeffs]

    output_JSON_object = {
        "result": encoded
    }
    return output_JSON_object
