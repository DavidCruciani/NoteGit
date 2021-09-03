import subprocess
import json
import os

md5file = "md5sum.txt"
pathHash = "HashLookupWindows"

if not os.path.isdir(pathHash):
    os.mkdir(pathHash)

with open(md5file, "r") as md5Read:
    lines = md5Read.readlines()
    for line in lines:
        lineSplit = line.split(" ")
        request = "%s -s -X 'GET' 'https://hashlookup.circl.lu/lookup/md5/%s' -H 'accept: application/json'" % ( "curl", lineSplit[0].rstrip("\n") )
        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()

        jsonResponse = json.loads(output.decode())

        if not "message" in jsonResponse.keys():
            with open(pathHash + "/" + lineSplit[0].rstrip("\n"), "w") as fileHash:
                fileHash.write(str(jsonResponse))