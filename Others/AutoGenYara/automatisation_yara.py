import string
import datetime
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", dest="a_file", help="Add a file to do one yara rule. File name must begin with @ and have an other @ after name of software: @PuTTY@machine")
    parser.add_argument("-d", "--directory", dest="directory", help="Pass a directory to do multiple yara rules")
    options = parser.parse_args()
    return options

#fichier = "C:\\Users\\David\Desktop\Stage Circl\Python Prog\@Chrome@strings"
#fichier = "C:\\Users\\David\Desktop\Stage Circl\Python Prog\@PuTTY@strings"
#fichier = "C:\\Users\\David\Desktop\Stage Circl\Python Prog\@WinRAR@_strings"
#fichier = "C:\\Users\\David\Desktop\Stage Circl\Python Prog\@PuTTY@s_Chrome_machine"
#fichier = "C:\\Users\\David\Desktop\Stage Circl\Python Prog\@PuTTY@machine"

#f = open(fichier)

option = get_arguments()

f = open(option.a_file)

file_strings = f.readlines()

s = list()

#print(fichier.split("@")[1])
try:
    #ext = fichier.split("@")
    ext = option.a_file.split("@")
except:
    print('il manque des @ dans le noms du fichier enregistré')
    print("exemple: C:\\Programe File\\@Chrome@strings")
    exit(1)

for i in range(0,len(file_strings)):
    if ((not len(file_strings[i].split(" ")) > 5 and not len(file_strings[i]) > 30) or (len(file_strings[i].split(" ")) == 1 and not len(file_strings[i]) > 50)) and ext[1] in file_strings[i] and file_strings[i] not in s:
            s.append(file_strings[i])

#print(file_strings)
"""print(len(file_strings))
print()
print(s)
print(len(s))"""

####Creation of yara rule

date = datetime.datetime.now()

rules = "rule " + ext[1] + "_" + ext[2] + "{\n\tmeta:\n\t\t"

rules += 'description = "Auto gene for ' + str(ext[1]) + '"\n\t\t'
rules += 'author = "David Cruciani"\n\t\t'
rules += "date = " + '"' + date.strftime('%Y-%m-%d') + '"' + "\n\t"

rules += "strings: \n"

r = -1

##Creation of regex to match the differents strings find earlier
for regle in s:
    reg = ""
    r+=1
    for car in regle:
        if car in string.ascii_letters or car in string.digits or car == " ":
            reg += car
        elif car in string.punctuation:
            reg += "\\" + car

    rules += "\t\t$s" + str(r) + " = " + "/" + reg + "/\n"

rules += "\tcondition:\n\t\t" + str(int(r/1.25)) + " of ($s*)\n}"

print(rules)

#exit(0)

###Save of the rule on the disk

path = ""
for i in option.a_file.split("\\")[:-1]:
    path += i + "\\"

yara_rule = open(path + ext[1] + "_" + ext[2] + ".yar","w")
yara_rule.write(rules)
yara_rule.close()