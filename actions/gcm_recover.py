from lib.finite_field import FFPoly
from lib.polynomial import Poly
from lib.cantor_zassenhaus import cantor_zassenhaus
from lib.aes_gcm import GHASH, pad

import base64

MAX_CZ_TRIES = 15

def factorize(equation):
    # Calculate expected number of factors
    d = equation.degree

    # Factorize polynomial
    factors = [equation]

    # Avoid duplicate factors
    def insert(factor):
        if any([factor == f for f in factors]): return
        factors.append(factor)

    while True:
        next_factor = None
        for key, f in enumerate(factors):
            if f.degree != 1:
                next_factor = factors.pop(key)
                break

        # If no factor > 1 was found, we are done
        if next_factor is None:
            break

        # Repeat until we have two factors
        k1, k2, ctr = None, None, 0
        while (k1 is None or k2 is None) and ctr < MAX_CZ_TRIES:
            k1, k2 = cantor_zassenhaus(equation, next_factor)
            ctr += 1
        if ctr == MAX_CZ_TRIES:
            continue
        assert k1*k2 == next_factor, "Factorization failed (k1*k2 != p)"

        insert(k1)
        insert(k2)

    return factors

def load(json_object):
    assert "nonce" in json_object, "Missing JSON value 'nonce'"

    assert "msg1" in json_object, "Missing JSON value 'msg1'"
    assert "ciphertext" in json_object["msg1"], "Missing JSON value 'ciphertext' in 'msg1'"
    assert "associated_data" in json_object["msg1"], "Missing JSON value 'associated_data' in 'msg1'"
    assert "auth_tag" in json_object["msg1"], "Missing JSON value 'auth_tag' in 'msg1'"

    assert "msg2" in json_object, "Missing JSON value 'msg2'"
    assert "ciphertext" in json_object["msg2"], "Missing JSON value 'ciphertext' in 'msg2'"
    assert "associated_data" in json_object["msg2"], "Missing JSON value 'associated_data' in 'msg2'"
    assert "auth_tag" in json_object["msg2"], "Missing JSON value 'auth_tag' in 'msg2'"

    assert "msg3" in json_object, "Missing JSON value 'msg3'"
    assert "ciphertext" in json_object["msg3"], "Missing JSON value 'ciphertext' in 'msg3'"
    assert "associated_data" in json_object["msg3"], "Missing JSON value 'associated_data' in 'msg3'"
    assert "auth_tag" in json_object["msg3"], "Missing JSON value 'auth_tag' in 'msg3'"

    assert "msg4" in json_object, "Missing JSON value 'msg4'"
    assert "ciphertext" in json_object["msg4"], "Missing JSON value 'ciphertext' in 'msg4'"
    assert "associated_data" in json_object["msg4"], "Missing JSON value 'associated_data' in 'msg4'"

    nonce = base64.b64decode(json_object["nonce"])

    c1 = base64.b64decode(json_object["msg1"]["ciphertext"])
    a_data1 = base64.b64decode(json_object["msg1"]["associated_data"])
    auth_tag_1 = base64.b64decode(json_object["msg1"]["auth_tag"])

    c2 = base64.b64decode(json_object["msg2"]["ciphertext"])
    a_data2 = base64.b64decode(json_object["msg2"]["associated_data"])
    auth_tag_2 = base64.b64decode(json_object["msg2"]["auth_tag"])

    c3 = base64.b64decode(json_object["msg3"]["ciphertext"])
    a_data3 = base64.b64decode(json_object["msg3"]["associated_data"])
    auth_tag_3 = base64.b64decode(json_object["msg3"]["auth_tag"])

    c4 = base64.b64decode(json_object["msg4"]["ciphertext"])
    a_data4 = base64.b64decode(json_object["msg4"]["associated_data"])

    # Split ciphertexts into n blocks (Reversed)
    U = [FFPoly(pad(c1[i:i+16])) for i in range(0, len(c1), 16)];U = U[::-1]
    V = [FFPoly(pad(c2[i:i+16])) for i in range(0, len(c2), 16)];V = V[::-1]
    W = [FFPoly(pad(c3[i:i+16])) for i in range(0, len(c3), 16)];W = W[::-1]

    # Split associated data into n blocks (Reversed)
    A = [FFPoly(pad(a_data1[i:i+16])) for i in range(0, len(a_data1), 16)];A = A[::-1]
    B = [FFPoly(pad(a_data2[i:i+16])) for i in range(0, len(a_data2), 16)];B = B[::-1]
    C = [FFPoly(pad(a_data3[i:i+16])) for i in range(0, len(a_data3), 16)];C = C[::-1]

    # Create auth tag polynomials
    TU = FFPoly(auth_tag_1)
    TV = FFPoly(auth_tag_2)
    TW = FFPoly(auth_tag_3)

    # Ciphertexts U, V, W
    # Auth tags TU, TV, TW
    # Associated data A, B, C

    # Example:
    # 1 Ciphertext, 1 AD
    #   TU = A1 H^3 + u1 H^2 + LH + EK(y0)
    # 2 Ciphertexts, 1 AD
    #   TV = B1 H^4 + v1 H^3 + v2 H^2 + LH + EK(y0)
    # Equation system:
    #  0 =          A1 H^3 + u1 H^2 + L1H + EK(y0) - TU
    #  0 = B1 H^4 + v1 H^3 + v2 H^2 + L2H + EK(y0) - TV
    #  A1 H^3 + u1 H^2 + L1H + EK(y0) - TU = B1 H^4 + v1 H^3 + v2 H^2 + L2H + EK(y0) - TV (Remove EK(y0))
    #  A1 H^3 + u1 H^2 + L1H - TU = B1 H^4 + v1 H^3 + v2 H^2 + L2H - TV
    #  A1 H^3 + u1 H^2 + L1H - B1 H^4 - v1 H^3 - v2 H^2 - L2H - TU + TV = 0 
    #  - B1 H^4 + (A1 - v1) H^3 + (u1 - v2) H^2 + (L1 - L2) H^1 - TU + TV = 0
    #  - B1 H^4 + (A1 - v1) H^3 + (u1 - v2) H^2 + (L1 - L2) H^1 + (TV - TU) H^0 = 0

    # Build equation system (first elements in list have lowest degree)
    equation = []

    # Step 1: Add TV - TU to the equation
    equation.append(TV - TU)

    # Step 2: The length field is always the same so we can remove it
    length_u = FFPoly(GHASH(auth_tag_1, a_data1, c1).L)
    length_v = FFPoly(GHASH(auth_tag_2, a_data2, c2).L)
    equation.append(length_u - length_v)
    # Step 3: Collect all coefficients
    #         We have a variable number of ad and ciphertexts
    #         n ciphertext's (U) and then n ad's (A) (Message 1)
    #         m ciphertext's (V) and then m ad's (B) (Message 2)
    coefficients_1 = []
    for i in range(len(U)): coefficients_1.append(U[i])
    for i in range(len(A)): coefficients_1.append(A[i])
    coefficients_2 = []
    for i in range(len(V)): coefficients_2.append(V[i])
    for i in range(len(B)): coefficients_2.append(B[i])
    # For later use in step 7
    coefficients_3 = []
    for i in range(len(W)): coefficients_3.append(W[i])
    for i in range(len(C)): coefficients_3.append(C[i])

    # Step 4: Add all coefficients to the equation
    #         If #1 = #2 we always add c1[i] - c2[i]
    #         If #1 > #2 we add 0 - c2[i] after we added all c1[i]
    #         If #1 < #2 we add c1[i] - 0 after we added all c2[i]
    lc1 = len(coefficients_1)
    lc2 = len(coefficients_2)
    for i in range(max(lc1, lc2)):
        if i < lc1 and i < lc2:
            equation.append(coefficients_1[i] - coefficients_2[i])
        elif i < lc1:
            equation.append(coefficients_1[i])
        else:
            equation.append(-coefficients_2[i])

    # Step 5: Convert equation to polynomial and make monical
    poly = Poly(equation)
    if poly[-1] != 1:
        poly = poly / poly[-1]

    # Step 6: Factorize the polynomial to find the zero points
    # (H + Q1)(H + Q2)(H + Q3)(H + Q4) = - B1 H^4 + (A1 - v1) H^3 + (u1 - v2) H^2 + (TV - TU) H^0 = 0
    # Now one of the factors is H
    factors = factorize(poly)

    # Step 7: Find the correct H candidate
    H = None
    EKY0 = None
    for f in factors:
        h_candidate = f[0]

        # Build equation system for message 1 and 2
        # TU = A1 H^4 + U1 H^3 + U2 H^2 + LH + EK(y0)
        # - EK(y0) = A1 H^4 + U1 H^3 + U2 H^2 + LH - TU
        # EK(y0) = -A1 H^4 - U1 H^3 - U2 H^2 - LH + TU
        # Later check if TU matches the auth tag

        equation1 = []
        equation1.append(TU)
        ghash1 = GHASH(h_candidate.block, a_data1, c1)
        equation1.append(-FFPoly(ghash1.L))
        for c in coefficients_1:
            equation1.append(-c)

        # Convert equation1 to polynomial
        poly1 = Poly(equation1)

        # Solve the equation1 and compare the result with the auth tag
        y0_1 = poly1.solve([h_candidate] * len(poly1))


        # Now we have the encrypted y0 and insert it into the equation
        # TW = W1 H^4 + W2 H^3 + W3 H^2 + LH + EK(y0)
        equation2 = []
        equation2.append(y0_1)
        ghash2 = GHASH(h_candidate.block, a_data3, c3)
        equation2.append(FFPoly(ghash2.L))
        for c in coefficients_3:
            equation2.append(c)

        # Convert equation2 to polynomial
        poly2 = Poly(equation2)

        # Solve the equation2 and compare the result with the auth tag
        tw_cantidate = poly2.solve([h_candidate] * len(poly2))

        # Check if the auth tag matches
        if tw_cantidate == TW:
            H = h_candidate
            EKY0 = y0_1
            break

    # Step 8: Calculate the auth tag for message 4
    #       auth_tag = GHASH XOR EK(y0)
    ghash3 = GHASH(H.block, a_data4, c4)
    ghash3 = FFPoly(ghash3.digest())
    auth_tag_4 = ghash3 ^ EKY0

    output_JSON_object = {
        "msg4_tag": base64.b64encode(auth_tag_4.block).decode('utf-8')
    }
    return output_JSON_object
