import base64

class Bytenigma:
    def __init__(self, rotors, plaintext) -> list:
        self.rotors = rotors
        self.rotor_size = len(rotors[0])
        self.rotor_count = len(rotors)
        # Keep track of the offset for each rotor
        self.rotor_offsets = [0] * self.rotor_count
        # Precalculate the reverse lookup for each rotor
        # as calling .index() on each rotor O(n) is slow
        self.reverse_rotors = [[0 for _ in range(self.rotor_size)] for _ in range(self.rotor_count)]
        for i in range( self.rotor_count):
            for r_index, r_value in enumerate(self.rotors[i]):
                self.reverse_rotors[i][r_value] = r_index

        # Convert bytes into integer list
        self.stream = [i for i in plaintext]

    def encrypt(self):
        for i in range(len(self.stream)):
            self.stream[i] = self.transform(self.stream[i])
            self.rotate()
        return self.stream

    def transform(self, index):
        # Rotate input through all rotors (left)
        # Using a counter-based loop is faster than 'enumerate'
        ctr = 0
        for rotor in self.rotors:
            offset = self.rotor_offsets[ctr]
            index = rotor[(index + offset) % self.rotor_size]
            ctr += 1

        # Calculate bitwise complement (flip all bits)
        index = self.rotor_size - 1 - index

        # Rotate input through all rotors (right)
        rev_ctr = self.rotor_count - 1
        for rotor in reversed(self.reverse_rotors):
            offset = self.rotor_offsets[rev_ctr]
            '''
            This bit is tricky because we cannot offset the index.
            Instead we have to get the regular value at the index and
            subtract the offset and prevent from being negative
            '''
            index = (rotor[index] - offset)  % self.rotor_size
            rev_ctr -= 1

        return index

    # Recursively rotate all rotors
    def rotate(self, depth=0):
        offset = self.rotor_offsets[depth] % self.rotor_size
        self.rotor_offsets[depth] = offset + 1
        # If a zero overflows, we rotate the next rotor
        if self.rotors[depth][offset] == 0 and (depth + 1) < self.rotor_count:
            self.rotate(depth + 1)

def load(json_object):
    assert "input" in json_object, "Missing JSON value 'input'"
    assert "rotors" in json_object, "Missing JSON value 'rotors'"

    plaintext = base64.b64decode(json_object["input"])
    rotors = json_object["rotors"]

    cipher_bytes = Bytenigma(rotors, plaintext).encrypt()
    base64_bytes = base64.b64encode(bytes(cipher_bytes))

    output_JSON_object = {
        "output": base64_bytes.decode('utf-8')
    }
    return output_JSON_object