from lib.finite_field import FFPoly

import base64

def load(json_object):
    assert "block" in json_object, "Missing JSON value 'block'"

    block = base64.b64decode(json_object["block"])

    exponents = FFPoly(block).exponents

    output_JSON_object = {
        "exponents": exponents
    }
    return output_JSON_object
