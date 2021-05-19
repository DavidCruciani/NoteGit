import sys
import re

POLY64 = 0x92C64265D32139A4
CRCTable = list()

kg = dict()
pg = dict()

def initcrc64():
    for i in range(0,256):
        lv=i
        for j in range(0,8):
            fl = lv & 1
            lv = lv >> 1
            if fl==1:
                lv = lv ^ POLY64
        CRCTable.append(lv)

def crc64(data):
	crc = 0xFFFFFFFFFFFFFFFF
	while(len(data) > 0):
		c = ord(data[0])
		crc = (crc>>8) ^ CRCTable[ (crc ^ c) & 0xFF ]
		data = data[1:len(data)-1]
		#print(data)
	return hex(crc>>32).lstrip("0x").rstrip("L").upper() + hex((crc & 0xFFFFFFFF)).lstrip("0x").rstrip("L").upper()


def initknownguids():
    kg['FOLDERID_System'] = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}'
    kg['FOLDERID_SystemX86'] = '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}'
    kg['FOLDERID_Windows'] = '{F38BF404-1D43-42F2-9305-67DE0B28FC23}'

    kg['FOLDERID_ProgramFiles'] = '{905E63B6-C1BF-494E-B29C-65B732D3D21A}'
    kg['FOLDERID_ProgramFilesX64'] = '{6D809377-6AF0-444b-8957-A3773F02200E}'
    kg['FOLDERID_ProgramFilesX86'] = '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}'

    kg['FOLDERID_ProgramFilesCommon'] = '{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}'
    kg['FOLDERID_ProgramFilesCommonX64'] = '{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}'
    kg['FOLDERID_ProgramFilesCommonX86'] = '{DE974D24-D9C6-4D3E-BF91-F4455120B917}'

    #pg['%windir%\system32'] = '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}'
    #pg['%windir%\system32'] = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}'
    pg['%windir%'] = '{F38BF404-1D43-42F2-9305-67DE0B28FC23}'
    pg['%windir%\Resources'] = '{8AD10C31-2ADB-4296-A8F7-E4701232C972}'
    pg['%windir%\\resources\\0409'] = '{2A00375E-224C-49DE-B8D1-440DF7EF3DDC}'
    pg['%windir%\Fonts'] = '{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}'
    pg['%USERPROFILE%'] = '{5E6C858F-0E22-4760-9AFE-EA3317B67173}'
    pg['%USERPROFILE%\Searches'] = '{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}'
    pg['%USERPROFILE%\Saved Games'] = '{4C5C32FF-BB9D-43b0-B5B4-2D72E54EAAA4}'
    pg['%USERPROFILE%\Pictures'] = '{33E28130-4E1E-4676-835A-98395C3BC3BB}'
    pg['%USERPROFILE%\Pictures\Slide Shows'] = '{69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C}'
    pg['%USERPROFILE%\Pictures\Screenshots'] = '{b7bede81-df94-4682-a7d8-57a52620b86f}'
    pg['%USERPROFILE%\Music'] = '{4BD8D571-6D19-48D3-BE97-422220080E43}'
    pg['%USERPROFILE%\Music\Playlists'] = '{DE92C1C7-837F-4F69-A3BB-86E631204A23}'
    pg['%USERPROFILE%\Links'] = '{bfb9d5e0-c6a9-404c-b2b2-ae6db6af4968}'
    pg['%USERPROFILE%\Favorites'] = '{1777F761-68AD-4D8A-87BD-30B759FA33DD}'
    pg['%USERPROFILE%\Downloads'] = '{374DE290-123F-4565-9164-39C4925E467B}'
    pg['%USERPROFILE%\Desktop'] = '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}'
    pg['%USERPROFILE%\Contacts'] = '{56784854-C6CB-462b-8169-88E350ACB882}'
    pg['%USERPROFILE%\AppData\Roaming'] = '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}'
    pg['%USERPROFILE%\AppData\Roaming\Microsoft\Windows\AccountPictures'] = '{008ca0b1-55b4-4c56-b8a8-4de4b299d3be}'
    pg['%USERPROFILE%\AppData\LocalLow'] = '{A520A1A4-1780-4FF6-BD18-167343C5AF16}'
    pg['%USERPROFILE%\AppData\Local'] = '{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}'
    pg['%USERPROFILE%\AppData\Local\Microsoft\Windows\RoamingTiles'] = '{00BCFC5A-ED94-4e48-96A1-3F6217F21990}'
    pg['%USERPROFILE%\AppData\Local\Microsoft\Windows\RoamedTileImages'] = '{AAA8D5A5-F1D6-4259-BAA8-78E7EF60835E}'
    pg['%USERPROFILE%\AppData\Local\Microsoft\Windows\Application Shortcuts'] = '{A3918781-E5F2-4890-B3D9-A7E54332328C}'
    pg['%USERPROFILE%\AppData\Local\Microsoft\Windows Sidebar\Gadgets'] = '{A75D362E-50FC-4fb7-AC2C-A8BEAA314493}'
    pg['%SystemDrive%\\Users'] = '{0762D272-C50A-4BB0-A382-697DCD729B80}'
    pg['%SystemDrive%\\Users\Public'] = '{DFDF76A2-C82A-4D63-906A-5644AC457385}'
    pg['%SystemDrive%\\Users\%USERNAME%'] = '{5E6C858F-0E22-4760-9AFE-EA3317B67173}'
    pg['%SystemDrive%\ProgramData)'] = '{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}'
    pg['%PUBLIC%\Videos'] = '{2400183A-6185-49FB-A2D8-4A392A602BA3}'
    pg['%PUBLIC%\Videos\Sample Videos'] = '{859EAD94-2E85-48AD-A71A-0969CB56A6CD}'
    pg['%PUBLIC%\RecordedTV.library-ms'] = '{1A6FDBA2-F42D-4358-A798-B74D745926C5}'
    pg['%PUBLIC%\Pictures'] = '{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}'
    pg['%PUBLIC%\Pictures\Sample Pictures'] = '{C4900540-2379-4C75-844B-64E6FAF8716B}'
    pg['%PUBLIC%\Music'] = '{3214FAB5-9757-4298-BB61-92A9DEAA44FF}'
    pg['%PUBLIC%\Music\Sample Playlists'] = '{15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5}'
    pg['%PUBLIC%\Music\Sample Music'] = '{B250C668-F57D-4EE1-A63C-290EE7D1AA1F}'
    pg['%PUBLIC%\Downloads'] = '{3D644C9B-1FB8-4f30-9B45-F670235F79C0}'
    pg['%PUBLIC%\Documents'] = '{ED4824AF-DCE4-45A8-81E2-FC7965083634}'
    pg['%PUBLIC%\Desktop'] = '{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}'
    pg['%PUBLIC%\AccountPictures'] = '{0482af6c-08f1-4c34-8c90-e17ec98b1e17}'
    pg['%PUBLIC%'] = '{DFDF76A2-C82A-4D63-906A-5644AC457385}'
    pg['%ProgramFiles%\Windows Sidebar\Gadgets'] = '{7B396E54-9EC5-4300-BE0A-2482EBAE1A26}'
    #pg['%ProgramFiles%\Common Files'] = '{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}'
    #pg['%ProgramFiles%\Common Files'] = '{DE974D24-D9C6-4D3E-BF91-F4455120B917}'
    #pg['%ProgramFiles%\Common Files'] = '{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}'
    #pg['%ProgramFiles%'] = '{905e63b6-c1bf-494e-b29c-65b732d3d21a}'
    #pg['%ProgramFiles%'] = '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}'
    #pg['%ProgramFiles%'] = '{6D809377-6AF0-444b-8957-A3773F02200E}'
    pg['%ProgramData%'] = '{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}'
    pg['%LOCALAPPDATA%'] = '{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}'
    pg['%LOCALAPPDATA%\Programs'] = '{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}'
    pg['%LOCALAPPDATA%\Programs\Common'] = '{BCBD3057-CA5C-4622-B42D-BC56DB0AE516}'
    pg['%LOCALAPPDATA%\Microsoft\Windows\Temporary Internet Files'] = '{352481E8-33BE-4251-BA85-6007CAEDCF9D}'
    pg['%LOCALAPPDATA%\Microsoft\Windows\Ringtones'] = '{C870044B-F49E-4126-A9C3-B52A1FF411E8}'
    pg['%LOCALAPPDATA%\Microsoft\Windows\History'] = '{D9DC8A3B-B784-432E-A781-5A1130A75963}'
    pg['%LOCALAPPDATA%\Microsoft\Windows\GameExplorer'] = '{054FAE61-4DD8-4787-80B6-090220C4B700}'
    pg['%LOCALAPPDATA%\Microsoft\Windows\Burn\Burn'] = '{9E52AB10-F80D-49DF-ACB8-4330F5687855}'
    pg['%LOCALAPPDATA%\Microsoft\Windows Photo Gallery\Original Images'] = '{2C36C0AA-5812-4b87-BFD0-4CD0DFB19B39}'
    pg['%APPDATA%'] = '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}'
    pg['%APPDATA%\Microsoft\Windows\Templates'] = '{A63293E8-664E-48DB-A079-DF759E0509F7}'
    pg['%APPDATA%\Microsoft\Windows\Start Menu'] = '{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}'
    pg['%APPDATA%\Microsoft\Windows\Start Menu\Programs'] = '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}'
    pg['%APPDATA%\Microsoft\Windows\Start Menu\Programs\StartUp'] = '{B97D20BB-F46A-4C97-BA10-5E3608430854}'
    pg['%APPDATA%\Microsoft\Windows\Start Menu\Programs\Administrative Tools'] = '{724EF170-A42D-4FEF-9F26-B60E846FBA4F}'
    pg['%APPDATA%\Microsoft\Windows\SendTo'] = '{8983036C-27C0-404B-8F08-102D10DCFD74}'
    pg['%APPDATA%\Microsoft\Windows\Recent'] = '{AE50C081-EBD2-438A-8655-8A092E34987A}'
    pg['%APPDATA%\Microsoft\Windows\Printer Shortcuts'] = '{9274BD8D-CFD1-41C3-B35E-B13F55A758F4}'
    pg['%APPDATA%\Microsoft\Windows\\Network Shortcuts'] = '{C5ABBF53-E17F-4121-8900-86626FC2C973}'
    pg['%APPDATA%\Microsoft\Windows\Libraries'] = '{1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE}'
    pg['%APPDATA%\Microsoft\Windows\Libraries\Videos.library-ms'] = '{491E922F-5643-4AF4-A7EB-4E7A138D8174}'
    pg['%APPDATA%\Microsoft\Windows\Libraries\Pictures.library-ms'] = '{A990AE9F-A03B-4E80-94BC-9912D7504104}'
    pg['%APPDATA%\Microsoft\Windows\Libraries\Music.library-ms'] = '{2112AB0A-C86A-4FFE-A368-0DE96E47012E}'
    pg['%APPDATA%\Microsoft\Windows\Libraries\Documents.library-ms'] = '{7B0DB17D-9CD2-4A93-9733-46CC89022E7C}'
    pg['%APPDATA%\Microsoft\Windows\Cookies'] = '{2B0F765D-C0E9-4171-908E-08A611B84FF6}'
    pg['%APPDATA%\Microsoft\Internet Explorer\Quick Launch'] = '{52a4f021-7b75-48a9-9f6b-4b87a210bc8f}'
    pg['%APPDATA%\Microsoft\Internet Explorer\Quick Launch\\User'] = '{9E3995AB-1F9C-4F13-B827-48B24B6C7174}'
    pg['%APPDATA%\Microsoft\Internet Explorer\Quick Launch\\User Pinned\ImplicitAppShortcuts'] = '{BCB5256F-79F6-4CEE-B725-DC34E402FD46}'
    pg['%ALLUSERSPROFILE%'] = '{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}'
    pg['%ALLUSERSPROFILE%\OEM Links'] = '{C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D}'
    pg['%ALLUSERSPROFILE%\Microsoft\Windows\Templates'] = '{B94237E7-57AC-4347-9151-B08C6C32D1F7}'
    pg['%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu'] = '{A4115719-D62E-491D-AA7C-E74B8BE3B067}'
    pg['%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs'] = '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}'
    pg['%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\StartUp'] = '{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}'
    pg['%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Administrative Tools'] = '{D0384E7D-BAC3-4797-8F14-CBA229B392B5}'
    pg['%ALLUSERSPROFILE%\Microsoft\Windows\Ringtones'] = '{E555AB60-153B-4D17-9F04-A5FE99FC15EC}'
    pg['%ALLUSERSPROFILE%\Microsoft\Windows\Libraries'] = '{48DAF80B-E6CF-4F4E-B800-0E69D84EE384}'
    pg['%ALLUSERSPROFILE%\Microsoft\Windows\GameExplorer'] = '{DEBF2536-E1A8-4c59-B6A2-414586476AEA}'
    pg['%ALLUSERSPROFILE%\Microsoft\Windows\DeviceMetadataStore'] = '{5CE4A5E9-E4EB-479D-B89F-130C02886155}'

def u(s):
	#print(s)
	"""x = re.match(r"(.)", s, re.IGNORECASE | re.DOTALL | re.MULTILINE)
	print(x)
	if x:
		s = re.sub(r"(.)", x.group(0) + "\x00", s, re.IGNORECASE | re.DOTALL | re.MULTILINE)
	print(s)"""
	s = " ".join(s)
	print(s)
	return s

def envpath(path):
	print("path: " + path)
	path = re.sub(r"C:.*?Windows", "%windir%", path, flags=re.IGNORECASE)
	path = re.sub(r"C:\\Users\\([^\\]+?)\\AppData\\Roaming", "%APPDATA%", path, flags=re.IGNORECASE)
	path = re.sub(r"C:\\Users\\([^\\]+?)\\AppData\\Local", "%LOCALAPPDATA%", path, flags=re.IGNORECASE)
	path = re.sub(r"C:\\Users\\([^\\]+?)", "%USERPROFILE%", path, flags=re.IGNORECASE)
	path = re.sub(r"C:\\Users\\Public", "%PUBLIC%", path, flags=re.IGNORECASE)
	path = re.sub(r"C:\\ProgramData", "%ALLUSERSPROFILE%", path, flags=re.IGNORECASE)
	path = re.sub(r"C:\\ProgramData", "%ProgramData%", path, flags=re.IGNORECASE)
	path = re.sub(r"C:\\Program Files \(x86\)", "%ProgramFiles%", path, flags=re.IGNORECASE)
	path = re.sub(r"C:\\Program Files", "%ProgramFiles%", path, flags=re.IGNORECASE)
	path = re.sub(r"C:", "%SystemDrive%", path, flags=re.IGNORECASE)
	return path.upper()

def normpath(path):
	#print("Avant: " + path)
	for k in pg:
		x = re.match(r"^{}(.*)$".format(re.escape(k)), path, flags=re.IGNORECASE)
		if x:
			path = re.sub(r"^{}(.*)$".format(re.escape(k)), pg[k] + x.group(1), path, flags=re.IGNORECASE)
	#print("Apres: " + path)
	return path


def msref():
  print ("\nThe path is ambigous and its appid depends on multiple factors (e.g. 32bit vs. 64bit) \nRefer to:\n   http://msdn.microsoft.com/en-us/library/windows/desktop/dd378457%28v=vs.85%29.aspx for details\n")


def print_appid(opath):
	#print("Avant Opath: " + opath)
	x = re.match(r'^(.+)\\([^\\]+)$', opath)
	z = re.match(r"\.", opath)
	if x:
		dire = x.group(1)
		fname = x.group(2)
		epath = envpath(dire)
		npath = normpath(epath)

		m = re.match(r"%windir%\\\\(system32|syswow64|sysnative)(\\.+)?$", epath, flags=re.IGNORECASE)
		x = re.match(r"%ProgramFiles%\\Common Files(\\.+)$", epath, flags=re.IGNORECASE)
		y = re.match(r"%ProgramFiles%(\\.+)$", epath, flags=re.IGNORECASE)
		if m:
			f=""
			if m.group(2):
				f = m.group(2)
			_print_appid(opath + " (1)    ", '%windir%\system32', kg['FOLDERID_System'   ] + f, fname)
			_print_appid(opath + " (2/X86)", '%windir%\system32', kg['FOLDERID_SystemX86'] + f, fname)
			msref()
		elif x:
			_print_appid (opath + ' (1)    ', '%ProgramFiles%\Common Files' + x.group(1), kg['FOLDERID_ProgramFilesCommon'   ] + x.group(1), fname)
			_print_appid (opath + ' (2/X64)', '%ProgramFiles%\Common Files' + x.group(1), kg['FOLDERID_ProgramFilesCommonX64'] + x.group(1), fname)
			_print_appid (opath + ' (3/x86)', '%ProgramFiles%\Common Files' + x.group(1), kg['FOLDERID_ProgramFilesCommonX86'] + x.group(1), fname)
			msref()
		elif y:
			_print_appid (opath + ' (1)    ', '%ProgramFiles%' + y.group(1), kg['FOLDERID_ProgramFiles'   ] + y.group(1), fname)
			_print_appid (opath + ' (2/X64)', '%ProgramFiles%' + y.group(1), kg['FOLDERID_ProgramFilesX64'] + y.group(1), fname)
			_print_appid (opath + ' (3/x86)', '%ProgramFiles%' + y.group(1), kg['FOLDERID_ProgramFilesX86'] + y.group(1), fname)
			msref()
		else:
			_print_appid (opath, epath, npath, fname)
	elif z:
		_print_appid (opath, opath, opath, '')
	else:
		print("\nProvide a proper full path!\n")
		exit(1)


def appid_calc(path):
	print("path: " + path)
	return crc64(u(path.upper()))

def _print_appid(opath, epath, npath, fname):
	if not (fname == ""):
		fname = "\\" + fname
	appid = appid_calc(npath + fname)
	print("\n")
	if not opath == "":
		print("%s\n" % (opath))
	if not (epath == opath):
		print("   --> %s%s\n" % (epath, fname))
	if ((not (npath == opath)) and (not (npath == epath))):
		print("   --> %s%s\n" % (npath, fname))
	print("\n APPID = %s" % (appid))
	



initcrc64()
initknownguids()

if len(sys.argv) == 2:
    print_appid(argv[1])
else:
    print_appid ("c:\\windows\\notepad.exe")
    print_appid (re.escape("c:\windows\system32\\notepad.exe"))
    print_appid (re.escape("c:\windows\syswow64\\notepad.exe"))
    print_appid ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe")
    print_appid ('c:\program files\Internet Explorer\iexplore.exe')
    print_appid ('MICROSOFT.INTERNETEXPLORER.DEFAULT')
