import os

if os.environ.get("CI") == "true":
    print("ACTIVATED_UNDER_CI")
else:
    print("DORMANT_BASELINE")
