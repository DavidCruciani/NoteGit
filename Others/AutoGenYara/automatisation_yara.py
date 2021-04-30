import string
import datetime
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", dest="a_file", help="Add a file to do one yara rule. File name must begin with @ and have an other @ after name of software: @PuTTY@machine")
    parser.add_argument("-d", "--directory", dest="directory", help="Pass a directory to do multiple yara rules")
    options = parser.parse_args()
    return options


####Creation of yara rule
def create_rule(ext, s):
    date = datetime.datetime.now()

    rules = "rule %s_%s {\n\tmeta:\n\t\t" % (ext[1], ext[2])

    rules += 'description = "Auto gene for %s"\n\t\t' % (str(ext[1]))
    rules += 'author = "David Cruciani"\n\t\t'
    rules += "date = %s\n\t" % (date.strftime('%Y-%m-%d'))

    rules += "strings: \n"

    ##Creation of regex to match the differents strings find earlier
    r = -1
    
    for regle in s:
        reg = ""
        r+=1
        for car in regle:
            if car in string.ascii_letters or car in string.digits or car == " ":
                reg += car
            elif car in string.punctuation:
                reg += "\\" + car

        rules += "\t\t$s%s = /%s/\n" % (str(r), reg)

    rules += "\tcondition:\n\t\t %s of ($s*)\n}" % (str(int(r/1.25)))

    return rules

###Save of the rule on the disk
def save_rule(path, ext):
    p = ""
    for i in path:
        p += i + "\\"

    yara_rule = open(p + ext[1] + "_" + ext[2] + ".yar","w")
    yara_rule.write(rules)
    yara_rule.close()






option = get_arguments()

f = open(option.a_file)
file_strings = f.readlines()

s = list()

try:
    ext = option.a_file.split("@")
except:
    print('il manque des @ dans le noms du fichier enregistré')
    print("exemple: C:\\Programe File\\@Chrome@strings")
    exit(1)

for i in range(0,len(file_strings)):
    if ((not len(file_strings[i].split(" ")) > 5 and not len(file_strings[i]) > 30) \
        or (len(file_strings[i].split(" ")) == 1 and not len(file_strings[i]) > 50)) \
        and ext[1] in file_strings[i] and file_strings[i] not in s:

            s.append(file_strings[i])

####Creation of yara rule
rules = create_rule(ext, s)

print(rules)
#exit(0)

###Save of the rule on the disk

save_rule(option.a_file.split("\\")[:-1], ext)
