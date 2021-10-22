#Path to the list that contains software to install: "nameOfPackage":"nameOfExe"
#applist = "B:\\git\\NoteGit\\Others\\AutoGenYara\\Serveur\\tests\listapp.txt"
applist = "/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/AutoGene/tests/app.txt"

pathToInstaller = "/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/ShareFolder_VM/Installer"

#Path to VBoxManage
VBoxManage = "VBoxManage"

#UUID of Windows VM
WindowsVM = "{4ca801cb-38ba-4b3b-b694-f77ed0a3c372}"
#Path to Windows VM
pathToWindowsVM = "/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/Windows10/10Win.vmdk"
#Path to folder share with Windows VM
pathToShareWindows = "/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/ShareFolder_VM/exe_extract"

#UUID of Linux VM
LinuxVM = ""

#Path to qemu to convert VM into raw format
qemu = "qemu-img"

#Path to folder who will contain vm in raw format
pathToConvert = "/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/ShareFolder_VM/convert/"
#Path to strings after linux execution
pathToStrings = "/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/ShareFolder_VM/Strings_out/"

#Path to xxd
xxd = "xxd"
#Path to cut
cut = "cut"
#Path to sed
sed = "sed"
#Path to curl
curl = "curl"

#Path to strings of Windows VM without software install
# pathToFirstStringsMachine = "C:\\Users\David\Desktop\Stage Circl\Python Prog\\first_machine_strings"
pathToFirstStringsMachine = "/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/string_first"

#Path to fls output of Windows VM without software install
pathToFirstFls = "/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/fls_first"

#Path to save yara rule on pc
pathToYaraSave = "/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/Yara"

#Path to the folder who will contains AsaReport
#pathToAsaReport = "/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/ShareFolder_VM/AsaReport"
pathToAsaReport = ""

#Option, feed hashlookup, default: N, possibility: N, Y
FeedHashlookup = "Y"

#Path to save the result to feed hashlookup
pathToFeedHashlookup = "/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/AutoGene/bin"

#Path to result of systeminfo
pathToSysInfo = "/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/ShareFolder_VM/sysinfo.txt"