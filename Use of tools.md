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

