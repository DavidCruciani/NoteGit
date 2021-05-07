import os
import sys
import time
import argparse
import subprocess

def get_arguments():
    parser = argparse.ArgumentParser(prog="Server", usage='%(prog)s [options] -q path to qem -v path to vm', description="Wait the end of the vm to do a copy into an other format using qemu")
    parser.add_argument("-q", "--qemu", dest="qemu", help="Path to qemu", required=True)
    parser.add_argument("-v", "--vm", dest="vm", help="Path to vm", required=True)
    parser.add_argument("-o", "--out", dest="out", help="Path to save the new disk format", default=".")
    options = parser.parse_args()
    return options

def runningVms():
    req = 'C:\\Program Files\Oracle\VirtualBox\VBoxManage.exe list runningvms'
    return subprocess.run(req, capture_output=True)

def readFile():
    f = open(os.path.dirname(sys.argv[0]) + "/tmp","r")
    l = f.readline().rstrip()
    f.close()
    return l


fapp = open("C:\\Users\David\Desktop\Stage Circl\Python Prog\listapp.txt", "r")
l_app = fapp.readlines()
line_count = 0
for line in l_app:
    if line != "\n":
        line_count += 1
fapp.close()

res = runningVms()

for i in range(0,line_count*2):
    print("boucle n: %s\n" % (i))
    res = runningVms()

    request = ['C:\\Program Files\Oracle\VirtualBox\VBoxManage.exe', 'startvm', '{235f9214-e871-4b75-b091-c90e53b32974}']
    if not '{235f9214-e871-4b75-b091-c90e53b32974}' in res.stdout.decode():
        ## Start windows machine
        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()

    ## wait windows machine to shutdown
    res = runningVms()

    #while len(res.stdout) != 0:
    while '{235f9214-e871-4b75-b091-c90e53b32974}' in res.stdout.decode():
        time.sleep(60)
        res = runningVms()

    print("Windows stop")


    ## Convert windows machine into raw format
    qemu = "B:\Téléchargement\Logiciel\qemu-img-win-x64-2_3_0\qemu-img.exe"
    vm = 'C:\\Users\David\Downloads\VM\PXE - Windows 10 _Cible_\PXE - Windows 10 [Cible]-disk001.vmdk'
    partage = "B:\VM\PartageVM\convert\\"
    status = readFile()

    convert_file = "%s%s_%s.img" %(partage, status.split(":")[1], status.split(":")[0])

    print("## Convertion ##")
    ############### Mettre plutot le nom de l'exe pour la machine linux pour faire un grep -i direct en fonction du nom
    res = subprocess.call([qemu, "convert", "-f", "vmdk", "-O", "raw", vm, convert_file])
    print("ok\n")


    res = runningVms()

    request = ['C:\\Program Files\Oracle\VirtualBox\VBoxManage.exe', 'startvm', '{9f5f2d55-619b-490c-9225-a6ee4945fd5e}']
    if not '{9f5f2d55-619b-490c-9225-a6ee4945fd5e}' in res.stdout.decode():
        ## Start ubuntu machine
        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()


    res = runningVms()

    while '{9f5f2d55-619b-490c-9225-a6ee4945fd5e}' in res.stdout.decode():
        time.sleep(60)
        res = runningVms()

    print("Ubuntu stop")

    ## Suppresson of the current tmp file 
    os.remove(os.path.dirname(sys.argv[0]) + "/tmp")
    ## Suppression of the current raw disk
    os.remove(convert_file)


## AutoGeneYara