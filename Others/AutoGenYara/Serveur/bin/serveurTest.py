import os
import re
import sys
import time
import flask
import pathlib
pathProg = pathlib.Path(__file__).parent.absolute()
s = ""
for i in re.split(r"/|\\", str(pathProg))[:-1]:
    s += i + "/"
sys.path.append(s + "etc")
import allVariables


app = flask.Flask(__name__)
#app.config["DEBUG"] = True

f = open(allVariables.applist, "r")
listapp = f.readlines()

lapp = dict()
list_app = list()
cp = -1

for l in listapp:
    l = l.split(":")
    lapp[l[0]] = l[1].rstrip(("\n"))

list_app = list(lapp.keys())


@app.route('/', methods=['GET'])
def home():
    return "<h1>AutoGene Yara</h1>"

@app.route('/installer', methods=['GET'])
def installer():
    global cp

    cp += 1
    try:
        loc = list_app[cp]
    except:
        exit(0)

    return '<div>{"%s":"%s"}</div>' % (list_app[cp], lapp[list_app[cp]])



if __name__ == '__main__':
    app.run(host=allVariables.host, port=int(allVariables.port))
