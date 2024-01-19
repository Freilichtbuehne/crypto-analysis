import socket, base64, time, struct, logging

class PaddingOracleClient:
    def __init__(self, hostname, port, iv, ciphertext, verbose=False, delay=0.0008, step_size=64):
        self.hostname = hostname
        self.port = port
        self.iv = iv
        self.ciphertext = ciphertext
        self.socket = None
        self.delay = delay
        # The step size can make the attack much more faster
        # With it we don't have to bruteforce all 256 values
        # and can instead bruteforce e.g. ony 64 values, check
        # if the padding was successful and if not, try with the
        # next 64 values. If set to low, the attack will take longer
        # because of the overhead of waiting for the servers response.
        # The ideal value is roughly 64.
        self.step_size = step_size
        self.logger = self.setup_logging(verbose)

    def setup_logging(self, verbose):
        loglevel = verbose and logging.DEBUG or logging.INFO
        logger = logging.getLogger(__name__)
        logger.setLevel(loglevel)
        if not logger.handlers:
            formatter = logging.Formatter('%(levelname)s: [CLIENT] %(message)s')
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.hostname, self.port))

        # send ciphertext
        self.logger.debug(f"Sending ciphertext: {self.ciphertext.hex()}")
        self.socket.sendall(bytes.fromhex(self.ciphertext.hex()))

    def xor(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def handle_false_positives(self, candidates):
        # used for checking single false positives for first byte

        # extract the candidate bytes
        candidates = [c[0] for c in candidates]

        # Test all candidates
        for candidate in candidates:
            if candidate < 0x01 or candidate > 0x10: continue

            if candidate == 0x10:
                return 0x10

            # Send blockclount to server
            self.logger.debug(f"Send packet count: {256}")
            self.socket.sendall(struct.pack("<H", 256))

            cur_len = candidate + 1

            for i in range(0, 256):
                message = "00" * (16 - 1 - candidate) + format(i, '02x') + format(candidate ^ cur_len, '02x') * (candidate)
                self.socket.sendall(bytes.fromhex(message))
                if self.delay > 0: time.sleep(self.delay)

            # Count the number of valid responses
            response = self.socket.recv(256)
            valid_responses = len([i for i in response if i == 1])
            self.logger.debug(f"Valid responses for {format(candidate, '02x')}: {valid_responses}")

            # If both are valid, we found the incorrect byte
            if 0 < valid_responses < 256: return candidate

        self.logger.error(f"Could not find correct byte")
        return candidates[0]

    def brute_force(self, dc=None, tries_left=None):
        # check if socket is still open
        if self.socket is None:
            self.logger.error(f"Server closed connection")
            return

        # initialize to prevent reusing the same variables
        if dc is None: dc = []
        if tries_left is None: tries_left = 256

        # we can get false positives if we bruteforce the first byte
        # so we have to do a full bruteforce for the first byte
        # to check how many candidates are valid
        stepsize = len(dc) == 0 and 256 or self.step_size

        # holding condition if all bytes are decrypted
        cur_len = len(dc)
        if cur_len == 16: return dc

        # xor with current padding length
        q_mod = [format(dc[i] ^ (cur_len + 1), '02x') for i in range(0, len(dc))]

        # calculate the number of packets to send
        new_tries_left = max(0, tries_left - stepsize)
        packet_count = min(tries_left, stepsize)

        assert packet_count > 0, "Packet count must be greater than 0"

        # tell server that n packets are following
        # packet count are two bytes little endian
        self.logger.debug(f"Send packet count: {packet_count}")
        self.socket.sendall(struct.pack("<H", packet_count))

        # bruteforce nth byte of padding (16 bytes total)
        self.logger.debug(f"Bruteforcing byte {cur_len + 1}")
        self.logger.debug(f"Q : {(15 - cur_len) * '00'  + 'xx' + ''.join(q_mod)}")
        self.logger.debug(f"p : {(16 - len(dc) - 1) * '??' + format(cur_len + 1, '02x') * (len(dc) + 1)}")
        self.logger.debug(f"DC: {(16 - len(dc)) * '??' + bytes(dc).hex()}")

        # continue where we left off
        for i in range(256 - tries_left, 256 - new_tries_left):
            message = (15 - cur_len) * "00"  + format(i, '02x') + "".join(q_mod)
            self.socket.sendall(bytes.fromhex(message))
            if self.delay > 0: time.sleep(self.delay)

        # receive first response
        # buffer size should be a power of 2
        response = self.socket.recv(stepsize)

        # Extract the nth byte that is non-zero
        found = []
        for i in range(0, len(response)):
            if response[i] == 0: continue
            index = 256 - tries_left + i
            found.append((index ^ (cur_len + 1), i))
        
        # Check for false positives
        if len(found) > 1:
            self.logger.debug(f"Found multiple bytes: {' '.join([format(i, '02x') for i, _ in found])}")
            true_byte = self.handle_false_positives(found)
            dc.insert(0, true_byte)
            self.logger.debug(f"Found: {format(true_byte, '02x')} Decrypt: {bytes(dc).hex()}")
            return self.brute_force(dc, 256)
        # Correct byte found
        elif len(found) == 1:
            dc.insert(0, found[0][0])
            self.logger.debug(f"Found: {format(found[0][1], '02x')} Decrypt: {bytes(dc).hex()}")
            return self.brute_force(dc, 256)

        # if no byte was found, try again with next step
        self.logger.debug(f"Nothing found, trying next step")
        return self.brute_force(dc, new_tries_left)

    def start(self):
        result = self.brute_force()

        # xor with iv
        result = self.xor(result, self.iv)
        self.logger.debug(f"XOR Result: {bytes(result).hex()}")

        return result

    def finish(self):
        if self.socket is None: return
        self.socket.close()

def load(json_object):
    assert "hostname" in json_object, "Missing JSON value 'hostname'"
    assert "port" in json_object, "Missing JSON value 'port'"
    assert "iv" in json_object, "Missing JSON value 'iv'"
    assert "ciphertext" in json_object, "Missing JSON value 'ciphertext'"

    hostname = json_object["hostname"]
    port = json_object["port"]
    iv = base64.b64decode(json_object["iv"])
    ciphertext = base64.b64decode(json_object["ciphertext"])

    client = PaddingOracleClient(hostname, port, iv, ciphertext, verbose=False, delay=0, step_size=256)
    client.connect()
    result = client.start()
    client.finish()

    base64_bytes = base64.b64encode(bytes(result))

    output_JSON_object = {
        "plaintext": base64_bytes.decode('utf-8')
    }
    return output_JSON_object