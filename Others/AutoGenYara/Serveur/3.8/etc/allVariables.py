#Path to the list that contains software to install: "nameOfPackage":"nameOfExe"
#applist = "B:\\git\\NoteGit\\Others\\AutoGenYara\\Serveur\\tests\listapp.txt"
applist = "B:\\git\\NoteGit\\Others\\AutoGenYara\\Serveur\\3.8\\tests\\app.txt"

blockProg = "B:\\git\\NoteGit\\Others\\AutoGenYara\\Serveur\\3.8\\etc\\blockProg.txt"

#Settings for server flask
host = "0.0.0.0"
port = "5000"

#Path to VBoxManage
VBoxManage = "C:\\Program Files\Oracle\VirtualBox\VBoxManage.exe"

#UUID of Windows VM
WindowsVM = "{235f9214-e871-4b75-b091-c90e53b32974}"
#Path to Windows VM
pathToWindowsVM = "C:\\Users\David\Downloads\VM\PXE - Windows 10 _Cible_\PXE - Windows 10 [Cible]-disk001.vmdk"
#Path to folder share with Windows VM
pathToShareWindows = "B:\VM\PartageVM\exe_extract"

#UUID of Linux VM
LinuxVM = "{9f5f2d55-619b-490c-9225-a6ee4945fd5e}"

#Path to qemu to convert VM into raw format
qemu = "B:\Téléchargement\Logiciel\qemu-img-win-x64-2_3_0\qemu-img.exe"

#Path to folder who will contain vm in raw format
pathToConvert = "B:\VM\PartageVM\convert\\"
#Path to strings after linux execution
pathToStrings = "B:\VM\PartageVM\Strings_out\\"

#Path to xxd
xxd = "B:\\Téléchargement\\Logiciel\\linux_command\\xxd.exe"
#Path to cut
cut = "B:\\Téléchargement\\Logiciel\\linux_command\\cut.exe"

#Path to strings of Windows VM without software install
# pathToFirstStringsMachine = "C:\\Users\David\Desktop\Stage Circl\Python Prog\\first_machine_strings"
pathToFirstStringsMachine = "B:\\VM\\PartageVM\\Windows10_first\\string_first_7zip"

#Path to fls output of Windows VM without software install
pathToFirstFls = "C:\\Users\David\Desktop\Stage Circl\Python Prog\\fls_first"

#Path to save yara rule on pc
pathToYaraSave = "B:\Téléchargement\Yara"