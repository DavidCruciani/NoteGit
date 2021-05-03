import os
import re
import string
import argparse
import datetime


def get_arguments():
    parser = argparse.ArgumentParser(prog="AutoGenYara", usage='%(prog)s [options] -f path to file', description="Create yara rule")
    parser.add_argument("-f", "--file", dest="a_file", help="Add a file to do one yara rule. File name must begin with @ and have an other @ after name of software: @PuTTY@machine")
    parser.add_argument("-d", "--directory", dest="directory", help="Pass a directory to do multiple yara rules")
    parser.add_argument("-m", "--machine", dest="machine", help="Pass a file that contains strings about the software of a machine at first state, without software install. strings first_machine > first; grep -i 'soft' first")
    parser.add_argument("-o", "--out", dest="out", help="Path to save yara rule generate")
    options = parser.parse_args()
    return options


####Creation of yara rule
def create_rule(ext, s, flag):
    date = datetime.datetime.now()

    ##Headers of yara rule
    rules = "rule %s_%s {\n\tmeta:\n\t\t" % (ext[1], ext[2])

    rules += 'description = "Auto gene for %s"\n\t\t' % (str(ext[1]))
    rules += 'author = "David Cruciani"\n\t\t'
    rules += 'date = "' + date.strftime('%Y-%m-%d') + '"\n\t'

    rules += "strings: \n"

    ##Creation of regex to match the differents strings find earlier
    r = -1
    
    for regle in s:
        reg = ""
        r+=1
        for car in regle:
            if car in string.ascii_letters or car in string.digits or car == " " or car == "\t":
                reg += car
            elif car in string.punctuation:
                reg += "\\" + car
        ## if file is a tree, split to have only the interesting part 
        if flag:
            reg = str(reg).split("\t")[1]
 
        rules += "\t\t$s%s = /%s/\n" % (str(r), reg)

    ##End of yara rule
    ## 1.25 is a coefficient to match the rule, which leaves a margin of error
    rules += "\tcondition:\n\t\t %s of ($s*)\n}" % (str(int(r/1.25)))

    return rules

###Save of the rule on the disk
def save_rule(path, ext, rules, out):
    p = ""
    for i in path:
        p += i + "\\"

    ## -o
    if out:
        yara_rule = open("%s\\%s_%s.yar" % (out, ext[1], ext[2]), "w")
    else:
        yara_rule = open("%s%s_%s.yar" % (p, ext[1], ext[2]), "w")

    yara_rule.write(rules)
    yara_rule.close()


def file_create_rule(chemin, machine, out, flag = False):
    s = list()

    f = open(chemin, "r")
    file_strings = f.readlines()

    ## -m
    if machine:
        first = open(machine)
        full = first.readlines()    

    ## Extract the term to search
    try:
        ext = chemin.split("@")
    except:
        print('Missing @ in the file name')
        print("Example: C:\\Programe File\\@Chrome@strings")
        exit(1)

    for i in range(0,len(file_strings)):
        ## the file is not a tree
        if not flag:
            ## there's a file who contains some strings about a software on a virgin machine
            if machine:
                if ((not len(file_strings[i].split(" ")) > 5 and not len(file_strings[i]) > 30) \
                    or (len(file_strings[i].split(" ")) == 1 and not len(file_strings[i]) > 50)) \
                    and ((ext[1] in file_strings[i] or ext[1].lower() in file_strings[i]) and file_strings[i] not in s) and file_strings[i] not in full:

                        s.append(file_strings[i])
            else:
                if ((not len(file_strings[i].split(" ")) > 5 and not len(file_strings[i]) > 30) \
                    or (len(file_strings[i].split(" ")) == 1 and not len(file_strings[i]) > 50)) \
                    and (ext[1] in file_strings[i] or ext[1].lower() in file_strings[i]) and file_strings[i] not in s:

                        s.append(file_strings[i])
        else:
            if (ext[1] in file_strings[i] or ext[1].lower() in file_strings[i] or ext[1].upper() in file_strings[i]) and file_strings[i] not in s:

                s.append(file_strings[i])

    ## Suppression of the extension
    ext.append(str(ext[-1:][0].split(".")[0]))
    del(ext[-2:-1])

    ####Creation of yara rule
    rules = create_rule(ext, s, flag)

    print(rules)
    #exit(0)

    ###Save of the rule on the disk
    save_rule(chemin.split("\\")[:-1], ext, rules, out)


def inditif(fichier, machine, out):
    try:
        extension = fichier.split(".")[1]
    except:
        print("Missing extension")
        exit(1)

    ## the file is a tree
    if fichier.split(".")[1] == "tree":
        file_create_rule(fichier, machine, out, True)
    else:
        file_create_rule(fichier, machine, out)






option = get_arguments()

## -d
if option.directory:
    if os.path.isdir(option.directory):
        for content in os.listdir(option.directory):
            chemin = os.path.join(option.directory, content)
            if os.path.isfile(chemin):
                inditif(chemin, option.machine, option.out)

    else:
        print("This is not a directory")
## -f
elif option.a_file:
    if os.path.isfile(option.a_file):
        inditif(option.a_file, option.machine, option.out)

    else:
        print("This is not a file")
else:
    print("No arg pass try -h")
