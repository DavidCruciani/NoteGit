import time
import flask
import argparse

def get_arguments():
    parser = argparse.ArgumentParser(prog="Server", usage='%(prog)s [options] -l path to list', description="Server to distribute list of app")
    parser.add_argument("-ho", "--host", dest="host", help="Host you want, default: 0.0.0.0", default="0.0.0.0")
    parser.add_argument("-p", "--port", dest="port", help="Port you want, default: 5000", default="5000")
    parser.add_argument("-l", "--list", dest="list", help="List that the server will give", required=True)
    options = parser.parse_args()
    return options


app = flask.Flask(__name__)
app.config["DEBUG"] = True

option = get_arguments()
f = open(option.list)
listapp = f.readlines()

lapp = dict()
list_app = list()
flagun = False
cp = -1

for l in listapp:
    l = l.split(":")
    lapp[l[0]] = l[1].rstrip(("\n"))

list_app = list(lapp.keys())
#print(list_app)
#exit(0)

@app.route('/', methods=['GET'])
def home():
    return "<h1>AutoGene Yara</h1>"

@app.route('/installer', methods=['GET'])
def installer():
    global cp, flagun

    if flagun:
        return flask.redirect("/uninstaller")

    #flag = False
    cp += 1

    try:
        loc = list_app[cp]
    except:
        #flag = True
        flagun = True
        pass

    if flagun:
        cp = -1
        return '<div>{"stop":"stop"}</div>'
    else:
        return '<div>{"%s":"%s"}</div>' % (list_app[cp], lapp[list_app[cp]])


@app.route('/uninstaller', methods=['GET'])
def uninstaller():
    global cp, flagun
    
    cp += 1

    try:
        loc = list_app[cp]
    except:
        flagun = False
        pass

    if not flagun:
        cp = -1
        return '<div>{"stop":"stop"}</div>'
    else:
        return '<div>{"%s":"%s"}</div>' % (list_app[cp], lapp[list_app[cp]])



app.run(host=option.host, port=int(option.port))
