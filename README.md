# pentesting tools, written in python

<hr>

<h3>This repository contains program code for usage in red teaming.</h3>

<h2>t1</h2>

- port scanners - check for available ports given a certain range (modifiable) and the name/IP of the host. Utilises threading to improve efficiency

- ping - This pings the host given the host name/IP and the port to use.

<hr>

<h2>t2</h2>

- Key loggers - when run, the program creates a logs.enc file, encrypted by the key "key.key". the file is updated every time the user inputs a character, noting the character typed, the window the user is in, the process run, and the date/time. the file can be decrypted using the decrypt.py file.

<hr>

<h2>t3</h2>

- Ransomware - This program encrypts all the files in the given directory and can only be decrypted by running the decrypt.py file with the passcode at line 19.

- Worm - This program generates many junk files and folders and takes up a considerable amount of storage on the victim's PC

<hr>
