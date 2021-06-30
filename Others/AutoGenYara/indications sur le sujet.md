lister les applis

regle yara

décrire si une appli est installé sur un ssytem ou pas



clé de registre

détecter les logiciels supprimé

faire des fingerprint ou regarder les certif des dll, signautrer logiciel, ressource

ressource ressembl a originale mais pas meme signature



dans chaque repertoire .md, expliquer comment obtnue regle yara, logiciel utilisé pour obtenir



fin avril regle yara pour logiciel général



utiliser putty, chrome, outils portable(framasoft), mimicat





prendre quelque lignes en hexa d'un fichier et mettre dans yara pour voir si il match sur le disque





plugins PE dans yara pour acceder au headers

récup: signateur, version info

chercher plugin yara pour forensic

Automatisation de creation de regle



https://www.hexacorn.com/tools/appid_calc.pl

recrire en python



regle sur mimikatz





supprimer faux positif en regardanat avant install

faire un serveur qui donne prog a installer, faire un exe qui se connecte sur la machine qui install 

voir si etinte avec vboxmanage et faire faire un raw



faire un graphe d'explication de tous les prog que j'ai fais, couleur sur partie prog et autre git couleur sur regle

recup version installé par chocolatey

metre dans metadata de regle yara

generer un uuid sur les regle dans les meta



libvirt 

headless



tikz latex pour graphe

https://www.commentcamarche.net/faq/8447-automatiser-des-taches-avec-init-et-cron#lancer-une-tache-au-demarrage-init



command to search exe path in machine

cd / & dir /s /b winrar.exe

copy winrar.exe PartageVM

http://unxutils.sourceforge.net/



 VBoxManage guestproperty enumerate Windows10_2





- [ ] 2 set de strings (les vérif et les non vérif)
- [x] ajouter uuid
- [x] blacklist
- [ ] installer les moins installé de chocolatey
- [x] ajouter liste de base pour arborescence
- [ ] tester regles sur machine
- [ ] faire diff entre install et new install 
- [x] garphe pour expliquer étape + faire
- [x] changer le nom de exe dans le cas de blockProg
- [ ] lister tous les fichier créé avec l'install et faire un md5 ou sha-1 de tous les fichiers: git status, untracked files



carton+ malwaredb



github action pour tester le code 



mettre un gros fichier pour ecraser ce qui a été supprimé sur le disque

utiliser cpe pour identifier version et vulnerabilite



changer le client, fichier avec install/uninstall en nom et dedans écrire ce qu'il faut installer

https://www.tarma.com/tools/uninstall



-----------

refaire une machine vraiment de base

yara -d pour passer parametre

calculer les paramtètres optimales



instaler putty faire conversion faire 5 reboot

insatller soft a chaque reboot

regadrer quand match plu

https://docs.microsoft.com/en-us/sysinternals/downloads/sync

insatller sync, insatller soft, désinstall et lancer sync



Titre : improving forensic triage

"Pour trier mes merde"

