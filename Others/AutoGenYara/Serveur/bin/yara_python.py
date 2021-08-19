import ast 
import re
import sys
import pathlib
pathProg = pathlib.Path(__file__).parent.absolute()
pathWork = ""
for i in re.split(r"/|\\", str(pathProg))[:-1]:
    pathWork += i + "/"
sys.path.append(pathWork + "etc")

with open(pathWork + "etc/MultiSoft.txt", "r") as MultiSoft:
    lines = MultiSoft.readlines()
    for l in lines:
        separator = l.split(":")
        soft = separator[1].split(",")
        for s in soft:
            print(s)
        print(separator[0])