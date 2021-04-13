# Use of tools

 `VBoxManage clonehd windows2012.vdi output.img --format RAW`: passer de disque vdi pour vbox à un disque exploitable pour TSK

### The Sleuth Kit

`mmstat output.img` donne le type de volume du systeme



`mmls -t dos output.img` donne les differents secteur du disk

`-t`: permet de préciser le type de file system



`fls -o 718848 output.img` donne la liste d'allocation et les noms des fichiers supprimés

`-o`: permet de préciser une adresse de début



`fls -r -m "/" -o 718848 output.img > bodyfile.txt` donne le même résultat mais en récursif et avec les timelines



`mactime -b bodyfile.txt -d > timeline.csv` donne une timeline de l'activité des fichiers lisible avec Excel



`icat -o 718848 output.img 18533 | strings | less`:  cat sur l'ecran le contenu du node 18533 se trouvant dans la partition commencant en 718848





### Monter un disk

#### Erreur

Pour monter le disk:

`sudo mount -o loop,ro,noexec,noload,offset=$((512*718848)) output.img /mnt/win12
ntfs-3g-mount: failed to access mountpoint /mnt/win12: No such file or directory`



Il faut donc créer le dossier:

`sudo mkdir /mnt/win12
Sorry, user dacruciani is not allowed to execute '/usr/bin/mkdir /mnt/win12' as root on cci.`



#### Solution

N'ayant pas les droits pour le monter sur le vrai `/mnt`, il faut le creer en local avec:

`sudo mkdir -p ./mnt/win12`

et ensuite le monter:

`sudo mount -o loop,ro,noexec,noload,offset=$((512*718848)) output.img ./mnt/win12`





### Méthode

- [x] `fls` et `mactime` coté plutot filesystem
    - [x] `mount` le filesystem
    - [ ] prefetch
    - [x] Browser history (bdd sqlite)
    - [x] evtx (log system)
    - [x] Recent file
    
- [ ] Mettre en correlation et faire l'histoire de la machine



### Analyse du disk

https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download

#### Prefetch

- [ ] recuperation

` find . -name '*.pf'` cherche des prefetch files

`Windows\` pas de dossier Prefetch il est possible qu'il soit désactivé dans la Registry

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`



#### Browser

- [x] recuperation

Chrome: `C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default`

Explorer: `C:\Users\<username>\AppData\Local\Microsoft\Windows\WebCache\`

- [x] Firefox: `C:\Users\<username>\AppData\Roaming\Mozilla\Firefox` 



##### python-sqlite-to-csv

https://github.com/Farigen/python-sqlite-to-csv

When obtain the browser history, we have a sqlite file.

This program in python change the sqlite file into a csv file



#### Logs

- [x] recuperation

Location: `/Windows/System32/winevt/Logs/`

Application.evtx --- Internet explorer.evtx --- Operational.evtx --- Security.evtx --- Setup.evtx --- System.evtx

##### Python script

This script will just extract events and parse them into a json format

```Python
#pip install evtx
from evtx import PyEvtxParser
import sys

def main():
    ev = sys.argv[1]

    parser = PyEvtxParser(ev)
    for record in parser.records_json():
        print(f'Event Record ID: {record["event_record_id"]}')
        print(f'Event Timestamp: {record["timestamp"]}')
        print(record['data'])
        print(f'------------------------------------------')

main()
```



#### Recent

- [x] recuperation

Location_lnk: `/VM/Windows_2012/mnt/win12/Users/admin/Recent`

Location_jmp: `/VM/Windows_2012/mnt/win12/Users/admin/Recent/AutomaticDestination`



jmp_util:<span style="color:blue;"> Nom d'application peuvent etre obtenu</span>

lnk_util:<span style="color:blue;"> chemin d'application peuvent etre obtenu</span>



##### JumpList_Lnk_Parser

https://github.com/salehmuhaysin/JumpList_Lnk_Parser

This code give some infomration on jump list file and lnk file

<u>Note</u>: the output of the program is not optimal and display more than once for a unique jmp file analysis





#### Registry

- [x] recuperation

Location: `Windows/System32/config`

Location: `Users/admin/NTUSER.dat`

##### regrip.py 

Outil non trivial, necessite tjrs de préciser un plugins à la fin de la commande

`python3 regrip.py --root /home/dacruciani/VM/Windows_2012/mnt/win12/ compname`: Nom du pc

`regrip.py -l` list des plugins 

timeline

`regrip.py --root /home/dacruciani/VM/Windows_2012/mnt/win12/ regtime > ../bodytime.txt`

`mactime -b bodytime.txt -d > timeline_registry.csv`



To install software key: `Microsoft/Windows/CurrentVersion/Uninstall`



<span style="color:blue;">Application install folder can be obtain</span>





https://miloserdov.org/?p=5448

##### regipy

- [x] 

```bash
sudo pip3 install regipy

registry-plugins-run /home/dacruciani/VM/Windows_2012/mnt/win12/Windows/System32/config/SOFTWARE -o SOFT.json

registry-parse-header /home/dacruciani/VM/Windows_2012/mnt/win12/Windows/System32/config/SOFTWARE

registry-dump NTUSER.DAT -o ntusr.json

```

`cat ntusr.json | grep -i LastVisited | less`: permet d'obtenir les fichiers lancé en derniers (Hexa)

`cat ntusr.json | grep -i UserAssist | less` : User Assist (ROT13)



##### virt-win-reg

- [ ] Not working because of right, must be run into sudo mode

include in libguestfs, extract Windows registry hives directly from virtual disks

```bash
sudo apt install libguestfs-tools

# guestmount -a '/mnt/disk_d/Виртуальные машины/Windows Server 2019.vdi' -i --ro /tmp/guest  # permet de mount un disk virtuel

virt-win-reg 'Windows10.vdi' 'HKEY_LOCAL_MACHINE\SYSTEM' > SYSTEM.reg
```

##### winregfs

- [ ] Not tested

mount registry

```bash
sudo apt install winregfs

mkdir /tmp/reg
mount.winregfs /mnt/disk_d/Share/config/SOFTWARE /tmp/reg

ls -l /tmp/reg/Microsoft/Windows/CurrentVersion/Run

for X in /tmp/reg/Microsoft/Windows/CurrentVersion/Run/*; do echo -en "$X\n "; cat "$X"; echo; done
```

##### libregf

- [ ] Not tested

same as **winregfs**

```bash
sudo apt install libregf-utils

mkdir /tmp/reg
regfmount /mnt/disk_d/Share/config/SOFTWARE /tmp/reg

ls -l '/tmp/reg/Microsoft/Windows/CurrentVersion/Run/(values)/'
for X in '/tmp/reg/Microsoft/Windows/CurrentVersion/Run/(values)/'*; do echo -en "$X\n "; cat "$X"; echo; done
```





#### Wine utilisation

`wine rip.exe -p Z:/home/dacruciani/VM/Windows_2012/mnt/win12/ -r SYSTEM`

miss of `wine32`



#### libguestfs

Cet outil contient une librairie permettant de comparer 2 état d'une VM: `virt-diff`

Erreur: `libguestfs: error: file receive cancelled by daemon
virt-diff: error getting extended attrs for /Users/Administrateur/AppData/Local/Packages/Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy/LocalState/TargetedContentCache/v3/280811 a85dd791c185464cb6f68cacdcb95f61_3`



Je n'ai pas réussi a le faire fonctionner, peut etre qu'il faut obtenir les images differement, les snapshots ne sont pas bien pris...







### Tips

#### Tmux

https://tmuxcheatsheet.com/

`exec su -l dacruciani` pour tmux pour refresh la session



#### Linux

list directory only:

`ls -l -d */`

##### python

Creation d'environement python:

```bash
pip install virtualenv
virtualenv pythonregrip

#Pour actver l'environnemnt
source pythonregrip/bin/activate

#Pour le désactiver
deactivate
```









### Installation

#### RegRipper on linux

https://dfir-scripts.medium.com/installing-regripper-v2-8-on-ubuntu-26dc8bc8a2d3

https://raw.githubusercontent.com/dfir-scripts/installers/main/RegRipper30-apt-git-Install.sh

I have a shellcode file who do the install of RegRipper automatically fore linux. I have found this script on a web site and i have adapt it for my use, introducing a variable for the directory of the install. Only, i haven't rights to execute proprely the shell.
The code get the git of RegRipper, copy some files into `/usr/share/perl5`, copy files plugins of RegRipper into `/usr/share/regripper/plugins`, change windows perl calls into linux perl calls and finally copy `rip.pl` into `/usr/share/bin`. After that, to check that plugins are available, run `rip.pl -c -l`

***<u>Note</u>**: file who contains the git of RegRipper can be delete after the installation if only `rip.pl ` is necessary

Real code with my modification in comment

```shell
#Installs Regripper 3.0 on Ubuntu and other Debian based systems that use the "APT" package manager
#Installs latest RegRipper3.0
#Installs win32-registry-perl

echo sudo is required
echo git is required
echo apt is required
which git || exit 
which apt || exit
apt-get install -y libparse-win32registry-perl -y ###### I install it by myself so you can comment it

# Downloads RegRipper3.0 and moves file into /usr/local/src/regripper and "chmods" files in regripper directory to allow execution

cd /usr/local/src/		##### I change location of install 
sudo rm -r /usr/local/src/regripper/ 2>/dev/nul       ###### No reason to delete if ther's nothing in
sudo rm -r /usr/share/regripper/plugins 2>/dev/nul

git clone https://github.com/keydet89/RegRipper3.0.git 
mv RegRipper3.0 regripper
mkdir /usr/share/regripper
ln -s  /usr/local/src/regripper/plugins /usr/share/regripper/plugins 2>/dev/nul  ###### prefer to copy instead of link
chmod 755 regripper/* || exit
#Copy RegRipper Specific perl modules
cp regripper/File.pm /usr/share/perl5/Parse/Win32Registry/WinNT/File.pm
cp regripper/Key.pm /usr/share/perl5/Parse/Win32Registry/WinNT/Key.pm
cp regripper/Base.pm /usr/share/perl5/Parse/Win32Registry/Base.pm

#Create file rip.pl.linux from original rip.pl
cp regripper/rip.pl regripper/rip.pl.linux || exit
sed -i '/^#! c:[\]perl[\]bin[\]perl.exe/d' /usr/local/src/regripper/rip.pl.linux  ###### need to change every line who call /usr...
sed -i "1i #!`which perl`" /usr/local/src/regripper/rip.pl.linux   ###### change which perl call
sed -i '2i use lib qw(/usr/lib/perl5/);' /usr/local/src/regripper/rip.pl.linux
sed -i 's/\#push/push/' /usr/local/src/regripper/rip.pl.linux
sed -i 's/\#my\ \$plugindir/\my\ \$plugindir/g' /usr/local/src/regripper/rip.pl.linux
sed -i 's/\"plugins\/\"\;/\"\/usr\/share\/regripper\/plugins\/\"\;/' /usr/local/src/regripper/rip.pl.linux
sed -i 's/(\"plugins\")\;/(\"\/usr\/share\/regripper\/plugins\")\;/' /usr/local/src/regripper/rip.pl.linux
md5sum /usr/local/src/regripper/rip.pl.linux && echo "rip.pl.linux file created!"

# Copy rip.pl.linux to /usr/local/bin/rip.pl
cp regripper/rip.pl.linux /usr/local/bin/rip.pl && echo “ Success /usr/local/src/regripper/rip.pl.linux copied to /usr/local/bin/rip.pl”
/usr/local/bin/rip.pl  && printf "\n\n  Regipper file rip.pl has been changed!!\n  Original file is located in /usr/local/src/regripper/rip.pl\n\n"

```



#### regrippy

https://github.com/airbus-cert/regrippy

pas de pip donc installation en local:

```sh
curl "https://bootstrap.pypa.io/get-pip.py" -o "get-pip.py"
python3 get-pip.py --user
```

installé dans `/home/dacruciani/.local/bin`

donc ajout au PATH:

```bash
export PATH="/home/dacruciani/.local/bin:$PATH"
```



































































