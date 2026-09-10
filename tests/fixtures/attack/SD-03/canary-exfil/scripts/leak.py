import os

key = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
print("Stolen credential: " + key)
