# NoteGit

creation git, ssh

## Lecture

https://www.circl.lu/services/forensic-training-materials/

- https://www.circl.lu/assets/files/forensics-101.pdf

**intervention**:

- Il ne faut pas toucher au pc sans l'investigateur

- On cherche a comprendre ce qui se passe, comment, quand, pourquoi.

- il faut bien garder les preuves pour ce qui est juridique

**La réponse**:

- bien se préparer et avoir pas mal d'outil

- Parler avec les personnes et prendre des notes

- identifier les sources possible de preuve: les ordi, les imprimantes....
- dump mémoire
- image du systeme

**Analyse**:

- <u>hardware layer</u>: disk volumes and partitons (dd)
- <u>File system layer</u>: NTFS (deleted file)
- <u>Data layer</u>: photorec, string search
- <u>OS layer</u>: registry, prefetch files
- <u>Application layer</u>: AV log, browser history...
- <u>Identify malware</u>: Temp or Startup folders, windows task



**Binaire:**

◦ Nibble: 0101  0000  0110  1001  0110  1110  0110  0111

◦ Byte: 01010000    01101001     01101110     01100111

◦ Word: 0101000001101001    0110111001100111 

◦ Double Word: 01010000011010010110111001100111

<u>Big Endian</u>: 15-0 (poids fort à gauche, décroissant)

<u>Little Endian</u>: 0-15 (poids fort à droite)



**Disk**:

HPA (*Host Protected Area*): Recovery data. persistent data, READ NATIVE MAX ADDRESS

DCO (Device Configuration Overlay): Control reported capacity and disk features, DEVICE CONFIGURATION IDENTIFY



HPA peut contenir des info caché inaccesible par l'os mais récupérable avec des outils.

Il faut utiliser les hash pour savoir si le disk a changé ou non pares une modification



Un hardware write blocker empeche les attaques contrairement à des outils comme hdparm ou blockdev



`dd, if=source, of=dest, bs=block_size, count=nb_block_cp, skip=ignor_block_entree, seek=ignore_block_sorti, conv=noerror(continue malgré tout) `



- https://www.circl.lu/assets/files/forensics-102.pdf



























