#Installs Regripper 3.0 on Ubuntu and other Debian based systems that use the "APT" package manager
#Installs latest RegRipper3.0
#Installs win32-registry-perl

echo sudo is required
echo git is required
echo apt is required
which git || exit
which apt || exit
#apt-get install -y libparse-win32registry-perl -y

# Downloads RegRipper3.0 and moves file into /usr/local/src/regripper and "chmods" files in regripper directory to allow execution

#sudo rm -r /usr/share/regripper 2>/dev/nul
printf "\n"
git clone https://github.com/keydet89/RegRipper3.0.git 

mv RegRipper3.0 regripper
mkdir /usr/share/regripper

user="/home/david/bin/"

ln -s /home/david/bin/regripper/plugins /usr/share/regripper/plugins 2>/dev/nul
chmod 755 regripper/* || exit
#Copy RegRipper Specific perl modules
cp regripper/File.pm /usr/share/perl5/Parse/Win32Registry/WinNT/File.pm
cp regripper/Key.pm /usr/share/perl5/Parse/Win32Registry/WinNT/Key.pm
cp regripper/Base.pm /usr/share/perl5/Parse/Win32Registry/Base.pm

#Create file rip.pl.linux from original rip.pl

cp regripper/rip.pl regripper/rip.pl.linux || exit
sed -i '/^#! c:[\]perl[\]bin[\]perl.exe/d' ${user}regripper/rip.pl.linux
sed -i "1i #!$(which perl)" ${user}regripper/rip.pl.linux
sed -i '2i use lib qw(/usr/lib/perl5/);' ${user}regripper/rip.pl.linux
sed -i 's/\#push/push/' ${user}regripper/rip.pl.linux
sed -i 's/\#my\ \$plugindir/\my\ \$plugindir/g' ${user}regripper/rip.pl.linux
sed -i 's/\"plugins\/\"\;/\"\/usr\/share\/regripper\/plugins\/\"\;/' ${user}regripper/rip.pl.linux
sed -i 's/(\"plugins\")\;/(\"\/usr\/share\/regripper\/plugins\")\;/' ${user}regripper/rip.pl.linux
md5sum ${user}regripper/rip.pl.linux && echo "rip.pl.linux file created!"

# Copy rip.pl.linux to /regripper/bin/rip.pl
cp regripper/rip.pl.linux /usr/local/bin/rip.pl && echo “ Success ${user}regripper/rip.pl.linux copied to /usr/local/bin/rip.pl”
/usr/local/bin/rip.pl  && printf "\n\n  Regipper file rip.pl has been changed!!\n  Original file is located in /${user}regripper/rip.pl\n\n"
