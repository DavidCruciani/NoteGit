import time
import datetime
import argparse
import subprocess

def get_arguments():
    parser = argparse.ArgumentParser(prog="Server", usage='%(prog)s [options] -q path to qem -v path to vm', description="Wait the end of the vm to do a copy into an other format using qemu")
    parser.add_argument("-q", "--qemu", dest="qemu", help="Path to qemu", required=True)
    parser.add_argument("-v", "--vm", dest="vm", help="Path to vm", required=True)
    parser.add_argument("-o", "--out", dest="out", help="Path to save the new disk format", default=".")
    options = parser.parse_args()
    return options

fapp = open("C:\\Users\David\Desktop\Stage Circl\Python Prog\listapp.txt", "r")
line_count = 0
for line in fapp:
    if line != "\n":
        line_count += 1
fapp.close()

print(line_count)

exit(0)


for i in range(0,line_count*2):

    request = 'C:\\Program Files\Oracle\VirtualBox\VBoxManage.exe list runningvms'
    res = subprocess.run(request, capture_output=True)

    if not b"PXE - Windows 10" in res.stdout:
        ## Start windows machine
        request = ['C:\\Program Files\Oracle\VirtualBox\VBoxManage.exe', 'startvm', '{235f9214-e871-4b75-b091-c90e53b32974}']
        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()

    ## wait windows machine to shutdown
    request = 'C:\\Program Files\Oracle\VirtualBox\VBoxManage.exe list runningvms'
    res = subprocess.run(request, capture_output=True)

    #while len(res.stdout) != 0:
    while b"PXE - Windows 10" in res.stdout:
        time.sleep(5)
        res = subprocess.run(request, capture_output=True)

    print("c est bon elle est arretee")


    ## Convert windows machine into raw format
    qemu = "B:\Téléchargement\Logiciel\qemu-img-win-x64-2_3_0\qemu-img.exe"
    vm = 'C:\\Users\David\Downloads\VM\PXE - Windows 10 _Cible_\PXE - Windows 10 [Cible]-disk001.vmdk'
    partage = "B:\VM\PartageVM\convert\out.img"

    date = datetime.datetime.now()

    print("## Convertion ##")
    res = subprocess.call([qemu, "convert", "-f", "vmdk", "-O", "raw", vm, partage])
    print("ok\n")


    ## Start ubuntu machine
    request = ['C:\\Program Files\Oracle\VirtualBox\VBoxManage.exe', 'startvm', '{15493e51-053a-4c3a-8fb3-efd24d0878ff}']
    p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    p_status = p.wait()


## AutoGeneYara