rule PuTTY_uninstall {
	meta:
		description = "Auto gene for PuTTY"
		author = "David Cruciani"
		date = "2021-07-02"
		versionApp = "Release 0.75"
		uuid = "0f640653-bb32-48d5-a802-d5a5a22b9efa"
	strings: 
		$s0 = /putty\.exe\|a07396d107f471234/
		$s1 = /puttygen\.exe\|a8e024fc7459f5f3/
		$s2 = /simontatham\.puttywindows\_win32/
		$s3 = /simontatham\.puttypackageid/
		$s4 = /\|packageidsimontatham\.puttya/
		$s5 = /\|windows\_win32simontatham\.puttya/
		$s6 = /1Wwindows\_win32simontatham\.puttya/
		$s7 = /r\\x69\\u007\(\[\(\[\(Kputty\"XOR\.Tem88\,73\,65\,92XOR/
		$s8 = /PUTTY\.EXE/
		$s9 = /IDS\_HTMLOUTPUTTYPE\_OPTION/
		$s10 = /IDS\_HTMLOUTPUTTYPE\_SINGLEHTML/
		$s11 = /IDS\_HTMLOUTPUTTYPE\_MULTIPLEHTML/
		$s12 = /PuTTY Installer/
		$s13 = /PuTTY release 0\.75 installer/
	condition:
		10 of ($s*)
}