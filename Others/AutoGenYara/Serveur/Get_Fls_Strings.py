#!/bin/python3

import os
import time
import subprocess

def fls(cheminMachine, cheminOut):
	## get the longer partition
	request = "mmls -t dos %s | cut -c43-55 > %slength_partition" % (cheminMachine, cheminOut)
	subprocess.call(request, shell=True)
	
	f = open(cheminOut + "length_partition")
	lines = f.readlines()

	max = 0
	cp = 0
	cpmax = 0

	for line in lines:
		if line != "\n":
			try:
				if int(line) > max:
					max = int(line)
					cpmax = cp
			except:
				pass
		cp += 1
	
	## get the start of the longer partition
	request = "mmls -t dos %s | cut -c17-26 > %sstart_partition" % (cheminMachine, cheminOut)
	subprocess.call(request, shell=True)
	
	f2 = open(cheminOut + "start_partition", "r")
	ls = f2.readlines()

	offset = int(ls[cpmax].rstrip("\n"))


	r = "fls -r -o %s %s > %sfls_first" % (str(offset), cheminMachine, cheminOut)

	p = subprocess.Popen(r, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	p_status = p.wait()
	
	f.close()
	f2.close()

	os.remove("%slength_partition" % (cheminOut))
	os.remove("%sstart_partition" % (cheminOut))
	
def getStrings(appchemin, app, cheminOut, app_status):
	r = "strings %s | grep -i %s > %s%s" % (appchemin, app, cheminOut, app_status)
	print(r)
	
	p = subprocess.Popen(r, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	p_status = p.wait()



if __name__ == '__main__':
	chemin = "/media/sf_PartageVM/"

	cheminConvert = chemin + "convert/"
	cheminOut = chemin + "Strings_out/"

	for content in os.listdir(cheminConvert):
		appchemin = os.path.join(cheminConvert, content)
		if os.path.isfile(appchemin):
			fls(appchemin, cheminOut)
			app_status = content.split(".")[0]
			app = app_status.split("_")[0]

			getStrings(appchemin, app, cheminOut, app_status)
			
	print("c'est fini")

	time.sleep(20)

	subprocess.call("poweroff")
	
	
