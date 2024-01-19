from lib.finite_field import FFPoly

import base64

def load(json_object):
    assert "a" in json_object, "Missing JSON value 'a'"
    assert "b" in json_object, "Missing JSON value 'b'"

    a = FFPoly(base64.b64decode(json_object["a"]))
    b = FFPoly(base64.b64decode(json_object["b"]))

    c = a * b

    output_JSON_object = {
        "a_times_b": base64.b64encode(c.block).decode('utf-8')
    }
    return output_JSON_object
