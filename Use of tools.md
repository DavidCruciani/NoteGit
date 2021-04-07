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
- [x] prefetch
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

Firefox: `C:\Users\<username>\AppData\Roaming\Mozilla\Firefox`



#### Logs

- [x] recuperation

Application.evtx

Internet explorer.evtx

Operational.evtx

Security

Setup

System



#### Recent

- [ ] recuperation

Automatic dest

lnk











### Tips

#### Tmux

https://tmuxcheatsheet.com/

`exec su -l dacruciani` pour tmux pour refresh la session



#### Linux























