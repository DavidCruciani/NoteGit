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
    - [ ] filesystem contient plusieurs fois des metadata

- [ ] Mettre en correlation et faire l'histoire de la machine



### Analyse du disk

#### Prefetch

- [ ] recuperation

` find . -name '*.pf'` cherche des prefetch files

`Windows\` pas de dossier Prefetch il est possible qu'il soit désactivé dans la Registry



#### Browser

- [x] recuperation

Chrome: `C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default`

Explorer: `C:\Users\<username>\AppData\Local\Microsoft\Windows\WebCache\`

- [x] Firefox: `C:\Users\<username>\AppData\Roaming\Mozilla\Firefox` 



#### Logs

- [x] recuperation

Location: `/Windows/System32/winevt/Logs/`

Application.evtx --- Internet explorer.evtx --- Operational.evtx --- Security.evtx --- Setup.evtx --- System.evtx



#### Recent

- [x] recuperation

Location: `\Users\John\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`

- Jump list

- *.lnk











### Tips

#### Tmux

https://tmuxcheatsheet.com/

`exec su -l dacruciani` pour tmux pour refresh la session



#### Linux







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







