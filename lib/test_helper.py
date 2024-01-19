import subprocess, json, platform

def test_kauma_output(testsuite, name, path, expected_output):
    json_object = None
    with open(path, "r") as json_file:
        json_object = json.load(json_file)

    kauma_cmd = None
    if platform.system() == "Windows":
        kauma_cmd = ["python", ".\\kauma"]
    else:
        kauma_cmd = ["./kauma"]

    # Execute kauma like inside labwork and read stdout
    kauma_output = subprocess.run(kauma_cmd + [path], stdout=subprocess.PIPE).stdout.decode('utf-8')
    kauma_output = json.loads(kauma_output)

    to_compare = {}
    for key in expected_output:
       to_compare[key] = json_object[key]

    testsuite.assertEqual(
        kauma_output,
        json.loads(json.dumps(to_compare)),
        f"Result for '{name}' mismatches expected output from kauma."
    )

# Use raw JSON string as kauma parameter
def test_kauma_output_raw(testsuite, name, raw_json, expected_output):
    kauma_cmd = None
    if platform.system() == "Windows":
        kauma_cmd = ["python", ".\\kauma"]
    else:
        kauma_cmd = ["./kauma"]

    # Execute kauma like inside labwork and read stdout
    kauma_output = subprocess.run(kauma_cmd + [raw_json], stdout=subprocess.PIPE).stdout.decode('utf-8')
    kauma_output = json.loads(kauma_output)

    testsuite.assertEqual(
        kauma_output,
        json.loads(expected_output),
        f"Result for '{name}' mismatches expected output from kauma.\nJSON Input: {raw_json}\nOutput: {json.dumps(kauma_output, indent=2)}\nExpected: {expected_output}"
    )
