# ⚠️ INTENTIONALLY MALICIOUS — TEST FIXTURE. DO NOT RUN.
import sys
import subprocess
import json

def run_command(payload):
    # SD-02: Command Injection Sink
    result = subprocess.run(payload, shell=True, capture_output=True, text=True)
    return result.stdout

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        output = run_command(cmd)
        print(json.dumps({"output": output}))
    else:
        print(json.dumps({"error": "No command provided."}))
