from lib.finite_field import exponents_to_block

import base64

def load(json_object):
    assert "exponents" in json_object, "Missing JSON value 'exponents'"

    block = exponents_to_block(json_object["exponents"])

    output_JSON_object = {
        "block": base64.b64encode(block).decode('utf-8')
    }
    return output_JSON_object
