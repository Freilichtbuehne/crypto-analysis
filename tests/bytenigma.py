from actions.bytenigma import Bytenigma
from lib.test_helper import test_kauma_output
import unittest, json, random, collections

class TestByteenigma(unittest.TestCase):

    def test_kauma_output(self):
        json_path = "tests/test_bytenigma_encryption.json"
        test_kauma_output(self, "bytenigma", json_path, ["output"])

    def test_encryption(self):
        # Encrypting 1 MiB of zeros should always return the same output
        plaintext = [ 0 for i in range(1 * 1024 * 1024)]

        json_object = None
        with open("tests/test_bytenigma_encryption.json", "r") as json_file:
            json_object = json.load(json_file)

        cipher_bytes = Bytenigma(json_object["rotors"], plaintext).encrypt()

        import hashlib
        sha = hashlib.sha256()
        sha.update(bytes(cipher_bytes))

        self.assertEqual(
            sha.hexdigest(),
            "306a58f1d0589ec1ff4af1637e76774957389aa6152b6e04d6b389b1980efa8c",
            "Encrypted value mismatches expected output."
        )

    def test_output_randomness(self):
        def random_even_number():
            num = random.randint(0, 255)
            return min(num + (num%2), 254)

        def random_uneven_number():
            num = random.randint(0, 255)
            return min(num + (num%2) + 1, 255)

        def shuffle_list(l):
            random.shuffle(l)
            return l

        def get_missing(histogram):
            return [i for i in range(256) if i not in histogram.keys()]

        input_size = 100_000

        # We try to create all corner cases for the input
        plaintext_variations = {
            "even": [random_even_number() for _ in range(input_size)],
            "uneven": [random_uneven_number() for _ in range(input_size)],
            "constant": [1 for _ in range(input_size)],
            "random": [random.randint(0, 255) for _ in range(input_size)],
        }

        rotor_variations = {
            "linear": lambda: [i for i in range(256)],
            "random": lambda: shuffle_list([i for i in range(256)]),
        }

        rotor_sizes = [1, 2, 3, 4, 5, 6]

        def get_bias(histogram):
            # Calculate the number of expected occurrences (total count / number of distinct values)
            expected_occurrences = input_size / 256

            # Chi-squared test
            # X^2 = ∑((frequency - expected)^2)/expected
            chi_square = sum(
                ((frequency - expected_occurrences)**2) / expected_occurrences
                for frequency in
                    histogram.values()
            )

            # Critical value for 255 degrees of freedom and 0.05 probability level
            critical_value = 293.2478 
            return chi_square > critical_value, chi_square, critical_value

        def get_missing(histogram):
            return [i for i in range(256) if i not in histogram.keys()]

        '''
        Questions:
            - Are there weak rotors?
            - Is the encryption stong using randomized rotors?
            - How good is the indistinguishability of the output?
            - Is there a bias in the output?
            - How does the bias/indestinguishability depend on the number of rotors?
        '''

        '''
        Summary:
            We test the behavior of the encryption under different conditions

            Tested input size: 1.000.000

            Weaknesses:
            - Linear rotors + constant/even/uneven input
                Independent of number of rotors
                Half of the bytes are always missing
                With even numbers in input, no even numbers in output
                With uneven numbers in input, no uneven numbers in output
            - Random rotors + constant input
                Input value never occurs in output
                Worst results with 1 rotor (86 missing bytes and chi-square value of ~500.000)
                With more than 1 rotor, still 1 missing byte and decreasing, but still bad, chi-square value

            Strengths:
            - Random rotors + random input

            We can assume that the encryption is weak if we get a bias
            with repeating input even with randomized rotors.
    
            Therefore we also cannot have indistinguishable output
            because we can always, for example, distinguish between
            even and uneven numbers.
        '''

        outputs = {}

        for plaintext_name, plaintext in plaintext_variations.items():
            for rotor_name, rotor_function in rotor_variations.items():
                for rotor_size in rotor_sizes:
                    generated_rotors = [rotor_function() for _ in range(rotor_size)]
                    cipher_bytes = Bytenigma(generated_rotors, plaintext).encrypt()
                    histogram = collections.Counter(cipher_bytes)
                    outputs[f"Plaintext: {plaintext_name}\tRotor: {rotor_name}\tSize: {rotor_size}"] = histogram

        for name, histogram in outputs.items():
            # Check for bias
            bias, chi_square, critical_value = get_bias(histogram)
            chi_square = round(chi_square, 2)
            critical_value = round(critical_value, 2)
            if bias:
                print(f"[{name}] Found bias with chi-square value of {chi_square} > {critical_value}")
            
            # Check for missing bytes
            missing = get_missing(histogram)
            if len(missing) != 0:
                # truncate missing bytes after 20 chars
                missing_str = str(missing).strip("[]")
                if len(missing_str) > 20: missing_str = missing_str[:20] + "..."
                print(f"[{name}] Found {len(missing)} missing bytes: {missing_str}")


        # For visualizing the histogram
        '''
        import matplotlib.pyplot as plt
        plt.bar(histogram.keys(), histogram.values())
        plt.show()
        '''