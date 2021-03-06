rule PuTTY_uninstall {
	meta:
		description = "Auto gene for PuTTY"
		author = "David Cruciani"
		date = "2021-07-01"
		versionApp = "Release 0.75"
		uuid = "2f5bfbba-674b-474d-bbdd-6fbf37578286"
	strings: 
		$s0 = /putty\~/
		$s1 = /puttygen\~/
		$s2 = /putty web site\~/
		$s3 = /putty manual\~/
		$s4 = /putty\.exe\|a07396d107f471234/
		$s5 = /puttygen\.exe\|a8e024fc7459f5f3/
		$s6 = /simontatham\.puttypackageid/
		$s7 = /simontatham\.puttywindows\_win32/
		$s8 = /\|packageidsimontatham\.puttya/
		$s9 = /\|windows\_win32simontatham\.puttya/
		$s10 = /1Wwindows\_win32simontatham\.puttya/
		$s11 = /\*\|PuTTYB\*\|/
		$s12 = /Eputty/
		$s13 = /O\*\|PuTTY/
		$s14 = /\(Gputty w/
		$s15 = /siteOPuTTY W/
		$s16 = /\@SimonTatham\.PuTTY/
		$s17 = / PUTTY\(\~1/
		$s18 = /B  PUTTYM\~1\.LNK/
		$s19 = /B  PUTTYW\~1\.LNK/
		$s20 = /B  PuTTY\.lnk/
		$s21 = /B  PuTTYgen\.lnk/
		$s22 = /r\\x69\\u007\(\[\(\[\(Kputty\"XOR\.Tem88\,73\,65\,92XOR/
		$s23 = /PuTTY release 0\.75 \(64\-bit\)/
		$s24 = /putty\.msi/
		$s25 = /PuTTY release 0\.75 \(64\-bit\)/
		$s26 = /PuTTY64/
		$s27 = /C\:\\Program Files\\PuTTY\\/
		$s28 = /PUTTY\.EXE/
		$s29 = /PuTTY\-UsfH/
		$s30 = /PuTTY\-User\-Key\-FUser\-Key\-File\-2/
		$s31 = /puttygen\-pastekey/
		$s32 = /putty\-private\-key\-file\-mac\-key/
		$s33 = /PuTTY key format too new/
		$s34 = /puttygen\-savepriv/
		$s35 = /puttygen\-fingerprint/
		$s36 = /puttygen\-comment/
		$s37 = /puttygen\-conversions/
		$s38 = /PuTTYgen/
		$s39 = /PuTTYgen Error/
		$s40 = /PuTTYgen Fatal Error/
		$s41 = /puttygen\-save\-ppk\-version/
		$s42 = /pubkey\-puttygen/
		$s43 = /\%s\\putty\_\%lu\_\%llu\.chm/
		$s44 = /puttygen\-strength/
		$s45 = /Software\\SimonTatham\\PuTTY\\CHMPath/
		$s46 = /Software\\SimonTatham\\PuTTY64\\CHMPath/
		$s47 = /PuTTYgen Warning/
		$s48 = /puttygen\-save\-passphrase\-hashing/
		$s49 = /puttygen\-generate/
		$s50 = /puttygen\-passphrase/
		$s51 = /puttygen\-keytype/
		$s52 = /PuTTYgen Notice/
		$s53 = /puttygen\-load/
		$s54 = /puttygen\-savepub/
		$s55 = /Software\\SimonTatham\\PuTTY/
		$s56 = /\\PUTTY\.RND/
		$s57 = /PuTTY\-User\-Key\-File\-/
		$s58 = /PuTTY\-User\-Key\-File\-\%u\: \%s/
		$s59 = /   name\=\"PuTTYgen\"/
		$s60 = /PuTTY\-UsH/
		$s61 = /SSHCONNECTION\@putty\.projects\.tartarus\.org\-2\.0\-/
		$s62 = /Local\\putty\-connshare\-mutex/
		$s63 = /Software\\SimonTatham\\PuTTY\\SshHostKeys/
		$s64 = /Software\\SimonTatham\\PuTTY\\Sessions/
		$s65 = /winadj\@putty\.projects\.tartarus\.org/
		$s66 = /simple\@putty\.projects\.tartarus\.org/
		$s67 = /putty\.log/
		$s68 = /\\\\\.\\pipe\\putty\-connshare/
		$s69 = /SSHCONNECTION\@putty\.projects\.tartarus\.org\-/
		$s70 = /putty\.exH/
		$s71 = /PuTTY Key File Warning/
		$s72 = /\-restrict\_putty\_acl/
		$s73 = /\-restrict\-putty\-acl/
		$s74 = /reencrypt\@putty\.projects\.tartarus\.org/
		$s75 = /reencrypt\-all\@putty\.projects\.tartarus\.org/
		$s76 = /add\-ppk\@putty\.projects\.tartarus\.org/
		$s77 = /list\-extended\@putty\.projects\.tartarus\.org/
		$s78 = /Unable to execute PuTTY\!/
		$s79 = /PuTTY\_File/
		$s80 = /PuTTYgen\_File/
		$s81 = /PuTTY Installer/
		$s82 = /PuTTY release 0\.75 installer/
		$s83 = /PuTTYConfigBox/
		$s84 = /putty \%s\&\%p\:\%u/
		$s85 = /PuTTY remote printer output/
		$s86 = /Software\\SimonTatham\\PuTTY\\Jumplist/
		$s87 = /putty\%s\%s/
		$s88 = /putty \%s\@\%s/
		$s89 = /Connect to PuTTY session \'/
		$s90 = /PuTTYgen\.exe/
		$s91 = /   name\=\"PuTTY\"/
	condition:
		72 of ($s*)
}