rule PuTTY_install {
	meta:
		description = "Auto gene for PuTTY"
		author = "David Cruciani"
		date = "2021-07-02"
		versionApp = "Release 0.75"
		uuid = "6765da86-ecbf-43d3-9fd2-165885831866"
	strings: 
		$s0 = /putty\.exe\|a07396d107f471234/
		$s1 = /puttygen\.exe\|a8e024fc7459f5f3/
		$s2 = /simontatham\.puttywindows\_win3/
		$s3 = /\|packageidsimontatham\.puttya/
		$s4 = /\|windows\_win32simontatham\.puttya/
		$s5 = /1Wwindows\_win32simontatham\.puttya/
		$s6 = /simontatham\.puttywindows\_win32/
		$s7 = /simontatham\.puttypackageid/
		$s8 = /r\\x69\\u007\(\[\(\[\(Kputty\"XOR\.Tem88\,73\,65\,92XOR/
		$s9 = /PuTTY release 0\.75 \(64\-bit\)/
		$s10 = /PUTTY\.EXE/
		$s11 = /IDS\_HTMLOUTPUTTYPE\_OPTION/
		$s12 = /IDS\_HTMLOUTPUTTYPE\_SINGLEHTML/
		$s13 = /IDS\_HTMLOUTPUTTYPE\_MULTIPLEHTML/
		$s14 = /\+ d\/d 38088\-144\-5\:PuTTY/
		$s15 = /\+\+ r\/r 38092\-128\-3\:putty\.chm/
		$s16 = /\+\+ r\/r 38135\-128\-3\:putty\.exe/
	condition:
		12 of ($s*)
}