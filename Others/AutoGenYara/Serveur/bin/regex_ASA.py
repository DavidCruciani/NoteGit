import json
import subprocess

fileOpen = "B:/git/NoteGit/Others/putty_install_compare.json"
fileSed = "B:/Téléchargement/putty_install_compare.txt"

with open(fileOpen, "r") as write_file:
    jsonParse = json.loads(write_file.read())

with open("B:/git/NoteGit/Others/AutoGenYara/Serveur/etc/blocklistASA.txt", "r") as read_file:
    blocklistASA = read_file.readlines()

#print(blocklistASA)

path = ""
for i in jsonParse["results"]["FILE_CREATED"]:
    path += i["Compare"]["Path"] + "\n"

#print(path)
with open(fileSed, "w") as write_file:
    write_file.write(path)

request = ["B:/Téléchargement/Logiciel/linux_command/sed.exe", "-r", "-i"]
s = "/"
j = True
for i in blocklistASA:
    if j:
        s += i.rstrip("\n")
        j = False
    else:
        s += "|" + i.rstrip("\n")
s += "/d"
request.append(s)
request.append(fileSed)

print(request)

p = subprocess.Popen(request, stdout=subprocess.PIPE)
(output, err) = p.communicate()
p_status = p.wait()

#print(output)