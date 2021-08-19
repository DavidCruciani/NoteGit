import yara

file_rule = "B:\\Téléchargement\\Logiciel\\yara-v4.1.0-1612-win64\\rule.yar"
file_apply = "B:\\Téléchargement\\Logiciel\\yara-v4.1.0-1612-win64\\test.txt"

def yaracall(incr):
    rules = yara.compile(file_rule, externals= {'ext_var': incr})

    with open(file_apply, 'rb') as f:
        matches = rules.match(data=f.read())

    return matches

"""print(matches)
print(matches["main"][0]["matches"])"""

incr = 3
matches = yaracall(incr)

while not matches:
    incr -= 1
    matches = yaracall(incr)

print("Optimal value: " + str(incr))