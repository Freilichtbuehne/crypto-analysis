from lib.aes_gcm import AES_GCM

import base64

def load(json_object):
    assert "key" in json_object, "Missing JSON value 'key'"
    assert "nonce" in json_object, "Missing JSON value 'nonce'"
    assert "associated_data" in json_object, "Missing JSON value 'associated_data'"
    assert "plaintext" in json_object, "Missing JSON value 'plaintext'"

    key = base64.b64decode(json_object["key"])
    associated_data = base64.b64decode(json_object["associated_data"])
    nonce = base64.b64decode(json_object["nonce"])
    plaintext = base64.b64decode(json_object["plaintext"])

    gcm = AES_GCM(key, nonce)
    gcm.update(associated_data)
    ciphertext, auth_tag, y0, h = gcm.encrypt(plaintext)

    output_JSON_object = {
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "auth_tag": base64.b64encode(auth_tag).decode('utf-8'),
        "Y0": base64.b64encode(y0).decode('utf-8'),
        "H": base64.b64encode(h).decode('utf-8'),
    }
    return output_JSON_object
