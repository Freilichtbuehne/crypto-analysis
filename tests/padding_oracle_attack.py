from actions.padding_oracle_attack import PaddingOracleClient
from lib.padding_oracle_server import PaddingOracleServer
from lib.aes_cbc import AES_CBC

import unittest, json, base64, random, threading, time

class TestPaddingOracle(unittest.TestCase):

    def test_task_input(self):
        # test if we receive the correct output for the task 2.2 json file
        json_object = None
        with open("tests/test_padding_oracle.json", "r") as json_file:
            json_object = json.load(json_file)


        port = json_object["port"]
        iv = base64.b64decode(json_object["iv"])
        ciphertext = base64.b64decode(json_object["ciphertext"])

        client = PaddingOracleClient(hostname, port, iv, ciphertext, verbose=False)
        client.connect()
        result = client.start()
        client.finish()

        base64_bytes = base64.b64encode(bytes(result))

        self.assertEqual(base64_bytes, b"QUJDREVGR0hJSktMTU5PUA==")

    def test_decryption(self):
        json_object = None
        with open("tests/test_padding_oracle_task.json", "r") as json_file:
            json_object = json.load(json_file)

        port = 1234
        hostname = "x.x.x.x"

        def decrypt(iv, ciphertext):
            client = PaddingOracleClient(
                        hostname,
                        port,
                        iv,
                        ciphertext,
                        verbose=False,
                        step_size=64,
                    )
            client.connect()
            result = client.start()
            client.finish()
            return result

        for i_task in range(0, len(json_object)):
            iv = bytes.fromhex(json_object[i_task]["iv"])
            decrypted = [bytes.fromhex(c) for c in json_object[i_task]["decrypted"]]
            ciphertexts = [bytes.fromhex(c) for c in json_object[i_task]["ciphertexts"]]
            with self.subTest(i=i_task):
                results = []
                for i_ct in range(0, len(ciphertexts)):
                    # use iv for first block, otherwise use previous ciphertext
                    result = decrypt(
                        i_ct == 0 and iv or ciphertexts[i_ct - 1],
                        ciphertexts[i_ct]
                    )
                    results.append(result)

                print(f"Results of test {i_task+1}/{len(json_object)}:")
                # compare results with decrypted
                for i_ct in range(0, len(ciphertexts)):
                    self.assertEqual(results[i_ct], decrypted[i_ct])
                    print(f"[✔] {results[i_ct].hex()} == {decrypted[i_ct].hex()}")

    def test_bonus_task(self):
        port = 1234
        hostname = "x.x.x.x"

        def decrypt(iv, ciphertext):
            client = PaddingOracleClient(
                        hostname,
                        port,
                        iv,
                        ciphertext,
                        verbose=False,
                        step_size=64,
                    )
            client.connect()
            result = client.start()
            client.finish()
            return result

        iv = bytes.fromhex("c05932c29c49b9c4f768b805a5113c8a")
        ciphertexts = [
            bytes.fromhex("012840b0285e54c2944c34977919bb50"),
            bytes.fromhex("2d4d011376d0756d885dc4c06470e6b4"),
            bytes.fromhex("aa6a9790b01279bdb9c6f2b8fc7724e0")
        ]

        # "Das geht ja eigentlich." -- J. Kristof, 2023"
        plaintexts = [
            bytes.fromhex("224461732067656874206a6120656967"),
            bytes.fromhex("656e746c6963682e22202d2d204a2e20"),
            bytes.fromhex("4b726973746f662c2032303233030303")
        ]

        for i_ct in range(0, len(ciphertexts)):
            # use iv for first block, otherwise use previous ciphertext
            result = decrypt(
                i_ct == 0 and iv or ciphertexts[i_ct - 1],
                ciphertexts[i_ct]
            )
            self.assertEqual(result, plaintexts[i_ct])
            print(f"[✔] {result.hex()} == {plaintexts[i_ct].hex()}")

    def test_server_edgecases(self):
        hostname, port = "localhost", 18732
        random_plaintexts = []
        # Generate edge cases with all possible paddings:
        # 1. 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
        # 2. 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 02
        # 3. 00 00 00 00 00 00 00 00 00 00 00 00 00 03 03 03
        # ...
        for i in range(0, 0x10 + 1):
            plaintext = format(random.randint(0,255), '02x') * (16 - i) + format(i, '02x') * i
            random_plaintexts.append(bytes.fromhex(plaintext))
    
        random_iv = random.randbytes(16)
        random_key = random.randbytes(16)

        # calculate or ciphertext to decrypt
        aes = AES_CBC(random_key, random_iv)
        ciphertexts = [aes.encrypt_raw(random_plaintext) for random_plaintext in random_plaintexts]

        for i in range(0, len(random_plaintexts)):
            def run_server():
                server = PaddingOracleServer(hostname, port, random_key, random_iv, random_plaintexts[i])
                server.run()

            t = threading.Thread(target=run_server)
            t.start()

            # Wait until server started
            time.sleep(2)

            # Start or client against local server
            client = PaddingOracleClient(hostname, port, random_iv, ciphertexts[i], verbose=False, delay=0, step_size=256)
            client.connect()
            result = client.start()
            client.finish()

            # Wait for server to stop
            t.join()

            # xor with IV
            result = aes.xor(result, random_iv)

            # Compare output
            self.assertEqual(bytes(result), random_plaintexts[i])
            print(f"[✔] {random_plaintexts[i].hex()} == {bytes(result).hex()}")

    def test_server_random(self):
        hostname, port = "localhost", 18732
        random_plaintext = random.randbytes(16)
        random_iv = random.randbytes(16)
        random_key = random.randbytes(16)

        # calculate or ciphertext to decrypt
        aes = AES_CBC(random_key, random_iv)
        ciphertext = aes.encrypt_raw(random_plaintext)

        def run_server():
            server = PaddingOracleServer(hostname, port, random_key, random_iv, random_plaintext)
            server.run()

        t = threading.Thread(target=run_server)
        t.start()

        # Wait until server started
        time.sleep(2)

        # Start or client against local server
        client = PaddingOracleClient(hostname, port, random_iv, ciphertext, verbose=False, delay=0)
        client.connect()
        result = client.start()
        client.finish()

        # Wait for server to stop
        t.join()

        # xor with IV
        result = aes.xor(result, random_iv)

        # Compare output
        self.assertEqual(bytes(result), random_plaintext)
        print(f"[✔] {random_plaintext.hex()} == {bytes(result).hex()}")
