# NoteGit

creation git, ssh

## Lecture

https://www.circl.lu/services/forensic-training-materials/

### https://www.circl.lu/assets/files/forensics-101.pdf

##### intervention

- Il ne faut pas toucher au pc sans l'investigateur

- On cherche a comprendre ce qui se passe, comment, quand, pourquoi.

- il faut bien garder les preuves pour ce qui est juridique

##### La réponse

- bien se préparer et avoir pas mal d'outil

- Parler avec les personnes et prendre des notes

- identifier les sources possible de preuve: les ordi, les imprimantes....
- dump mémoire
- image du systeme

##### Analyse

- <u>hardware layer</u>: disk volumes and partitons (dd)
- <u>File system layer</u>: NTFS (deleted file)
- <u>Data layer</u>: photorec, string search
- <u>OS layer</u>: registry, prefetch files
- <u>Application layer</u>: AV log, browser history...
- <u>Identify malware</u>: Temp or Startup folders, windows task



##### Binaire

◦ Nibble: 0101  0000  0110  1001  0110  1110  0110  0111

◦ Byte: 01010000    01101001     01101110     01100111

◦ Word: 0101000001101001    0110111001100111 

◦ Double Word: 01010000011010010110111001100111

<u>Big Endian</u>: 15-0 (poids fort à gauche, décroissant)

<u>Little Endian</u>: 0-15 (poids fort à droite)



##### Disk

HPA (*Host Protected Area*): Recovery data. persistent data, READ NATIVE MAX ADDRESS

DCO (Device Configuration Overlay): Control reported capacity and disk features, DEVICE CONFIGURATION IDENTIFY



HPA peut contenir des info caché inaccesible par l'os mais récupérable avec des outils.

Il faut utiliser les hash pour savoir si le disk a changé ou non pares une modification



Un hardware write blocker empeche les attaques contrairement à des outils comme hdparm ou blockdev



`dd, if=source, of=dest, bs=block_size, count=nb_block_cp, skip=ignor_block_entree, seek=ignore_block_sorti, conv=noerror(continue malgré tout) `



### https://www.circl.lu/assets/files/forensics-102.pdf

TSk command at slide 11

##### File system

Explication d'un file system:

<img src="C:\Users\Matthias\git\NoteGit\image_readme\image-20210402082731325.png" alt="image-20210402082731325" style="zoom:67%;" />

Fichier supprimé:

<img src="C:\Users\Matthias\git\NoteGit\image_readme\image-20210402083608185.png" alt="image-20210402083608185" style="zoom:67%;" />



<img src="C:\Users\Matthias\git\NoteGit\image_readme\image-20210402083727451.png" alt="image-20210402083727451" style="zoom:67%;" />



`dd  if=deleted.dd  of=file2.txt  bs=32  skip=7122  count=2     --> This is Paula`

`dd  if=deleted.dd  of=file1.txt  bs=32  skip=7123  count=2     --> Paula World`





Structure de **FAT** :

<img src="C:\Users\Matthias\git\NoteGit\image_readme\image-20210402090048546.png" alt="image-20210402090048546" style="zoom:67%;" />

<img src="C:\Users\Matthias\git\NoteGit\image_readme\image-20210402090136587.png" alt="image-20210402090136587" style="zoom:67%;" />



Structure de **NTFS**:

<img src="C:\Users\Matthias\git\NoteGit\image_readme\image-20210402090317043.png" alt="image-20210402090317043" style="zoom:67%;" />

En **NTFS** tout est fichier



**MFT**: 1 record par fichier/dossier et chaque record=1024 bytes

<img src="C:\Users\Matthias\git\NoteGit\image_readme\image-20210402092117993.png" alt="image-20210402092117993" style="zoom:67%;" />



**$Bitmap** localisé au record 6 de MFT, il contient le status de chaque cluster (allocated or not), chaque bit represente 1 cluster

Byte 1: 0x13 == 0001  0100   -->  Cluster alloué: 3, 5

​												   --> Cluster non alloué: 1, 2, 4, 6, 7, 8

pour le cluster 4169:  4169 / 8 == 521.125    --> dans $Bitmap il faut donc regarder au byte 521 pour avoir ce cluster

si le fichier n'est pas supprimé:  1111  1111 et supprimé:  1110   0001



##### Timestamps

- FAT
    - Mac
        - M: Content last Modified
        - A: Content last Accessed
        - C: File Created
- NTFS
    - MACE or MACB
        - M: Content last Modified
        - A: Content last Accessed
        - C: File Created
        - E: MFT Entry last modified

command: `mactime`



##### Magic Bytes

Les données doivent etre séquentielles, si elles sont fragmentées, elles peuvent et cassées

un byte peut permettre d'identifier le fichier en cours d'analyse avec des en-tete défini et des fins définis aussi.



##### String Search

consiste a chercher des chaines de caractère lisible humainement, des formats, email, url, ip, bank



##### Resident, non resident

A file is resident if it is the primary copy of the file (as opposed to a backup copy) and it is stored on disk, regardless of whether the disk is online. A file is nonresident if it is stored only on a backup tape or if the file is a backup copy that is stored on another disk family.



### https://www.circl.lu/assets/files/forensics-103.pdf

#### Windows Registry

##### Registry

- SAM

    - Local users

- Security

    - Audit settings

- System

    - General system config
    - Program execution

- Software

    - Windows version, Profiles list
    - Scheduled Tasks
    - Program execution

    

**RegRipper** permet d'analyser les registres



###### User Hive

- Auto Start
    - Run
    - RunOnce
- Applications installed & uninstalled
- WordWheelQuery
    - user search on localhst
- Shell Bags
    - user preferences
- UserAssist
    - User Activities
- RecentDocs



#### Windows Event Logs

##### Event log

Event viewer, Event log Explorer, evtxexport (command line), evtx dump.py

Location: `/Windows/System32/winevt/Logs/` -->  `Security.evtx System.evtx Application.evtx`



##### Recycle.bin

`strings -el $NameOfFile` permet de récupérer le chemin jusqu'au fichier avant suppression

`type $NameOfFile` permet de faire la même chose (Windows)



##### LNK Files

Donne des information sur l'accès aux fichiers



##### XP Restore Points

- Backup of: 
    - Critical system files
    - Registry partially
    - Local user profiles 
    - But NO user data
- Created automatically: 
    - Every 24 hours 
    - Windows Update 
    - Installation of applications incl. driver
- For analyst
    - rp.log
    - Description of the cause
    - Time stamp
    - State of the system at different times



##### VSS - Volume Shadow Copy Service

Backup service:

- System files
- User data files
- Operates on block level



##### Prefetch Files

- Monitor an application when it starts
- Collect information about all resources needed

Permet de prouver qu'une application a bien été lancée.

Location: `/Windows/Prefetch`



Information inside prefetch file:

- Run count: How often launched
- Last time executed
- Application name incl. parameter
- Path to application and resources

analyse with tool like `prefetch.py`



##### Jump list

Similaire à `RecentDocs`

Document pour une application ouverte récemment

Location: `AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations`



Le nom des fichiers finissent par: `.automaticDextinations-ms`  --> `918e0ecb43d17e23.automaticDextinations-ms`

Les valeurs Hexa sont définis mondialement  --> `918e0ecb43d17e23 = Notepad.exe`



#### Basic Malware Analysis

##### PE - Portable Execution format

1. DOS Header 
2. PE Header
3. OPtional Header
4. Section Headers
5.  *.text* Section ( Program Code ) 
6.  *.idata* Section ( Importd Libs )
7.  *.rsrc* Section ( Strings, Images, ... ) 
8.  *.reloc* Section (Memory Translation ) 



tools useful: `file, efixtool, strings, virustotal, misp, Circl DMA`



#### Analysing files

tools useful Standard Linux: `file, efixtool, strings,md5sum, sha1sum, 7z`

Dedicated tools: `oledump.py,pdfid.py, pdf-parser.py, VirusTotal tools`



#### Live Response

##### Volatile Data

Memory dump



- System Time
    - `date /t & time /t`
- Loggedon Users
    - `net session`
    - `PsLoggedon.exe`
    - `logonsessions.exe`
- Open files
    - `net file`
- Network Connections and Status
    - `netstat -anob, -rn`
- Running Processes
    - `tasklist`
- Command history
    - `doskey /history`



#### Memory Forensics

- Dumpit (do the dump)

- Redline
- Volatility



### https://forensicswiki.xyz/wiki/index.php?title=Prefetch

Les fichiers Prefetch windows sont désignés pour améliorer le démarrage d'application.

Les fichiers Prefetch contiennent :

- Le nom de l'executable
- une liste unicode des DLLs utilisé par l'exe
- un compteur du nombre d'execution 
- et un timestamp de la dernière execution

**<u>Attention:</u>**  Les Prefetch sont désactivé par défault sur les SSD



Les noms de fichiers Prefetch suivent un format définis:

- Nom de l'exe en majuscule
- un tiret
- Un hash de 8 caractères de la localisation de l'appli
- une extension `.pf`



Les fichiers Prefetch contiennent:

- Le nom de l'exe, jusqu'à 29 caractères
- Le nombre d'execution ou le temps que l'appli à tournée
- Info sur le volume
- La taille du fichier Prefetch
- Le fichier et dossier où l'appli est lancé

Contiens également 2 timestamps:

- Le temps de la dernière execution de l'appli (version 26 garde les 7 dernières executions)
- Le temps de création du volume sur lequel le fichier Prefetch a été créé.



##### Registry Keys

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`

























