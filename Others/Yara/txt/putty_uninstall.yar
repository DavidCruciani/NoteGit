rule putty_uninstall {
	meta:
		description = "Auto gene for putty"
		author = "David Cruciani"
		date = "2021-06-07"
		versionApp = "Release 0.75"
		uuid = "965d9034-be70-4038-a2c6-3c17537e73ef"
	strings: 
		$s0 = /putty\~/
		$s1 = /puttygen\~/
		$s2 = /putty web site\~/
		$s3 = /putty manual\~/
		$s4 = /\/faq\-putty\-org\.html/
		$s5 = /\/faq\-puttyputty\.html/
		$s6 = /\/faq\-sillyputty\.html/
		$s7 = /\/pubkey\-puttygen\.html/
		$s8 = /\/puttygen\-comment\.html/
		$s9 = /\/puttygen\-conversions\.html/
		$s10 = /\/puttygen\-fingerprint\.html/
		$s11 = /\/puttygen\-generate\.html/
		$s12 = /\/puttygen\-generating\.html/
		$s13 = /\/puttygen\-keytype\.html/
		$s14 = /\/puttygen\-load\.html/
		$s15 = /\/puttygen\-passphrase\.html/
		$s16 = /\/puttygen\-pastekey\.html/
		$s17 = /\/puttygen\-primes\.html/
		$s18 = /\/puttygen\-save\-params\.html/
		$s19 = /\\\&\/puttygen\-save\-passphrase\-hashing\.html/
		$s20 = /\/puttygen\-save\-ppk\-version\.html/
		$s21 = /\/puttygen\-savepriv\.html/
		$s22 = /\/puttygen\-savepub\.html/
		$s23 = /\/puttygen\-strength\.html/
		$s24 = /\*\|\*\|putty\.exe9220/
		$s25 = /\*\|putty\*\|puuty7369/
		$s26 = /\*\|putty\*\|putyy6305/
		$s27 = /putty\.install\.nuspecPK/
		$s28 = /tools\/putty\-64bit\-0\.75\-installer\.msiPK/
		$s29 = /tools\/putty\-arm64\-0\.75\-installer\.msiPK/
		$s30 = /putty\.install\.nuspec /
		$s31 = /simontatham\.puttypackageid/
		$s32 = /simontatham\.puttywindows\_win32/
		$s33 = /packageidsimontatham\.putty\`/
		$s34 = /windows\_win32simontatham\.putty\`/
		$s35 = /SSHCONNECTION\@putty\.projects\.tartarus\.org\-2\.0\-/
		$s36 = /putty\-private\-key\-file\-mac\-key/
		$s37 = /Local\\putty\-connshare\-mutex/
		$s38 = /winadj\@putty\.projects\.tartarus\.org/
		$s39 = /simple\@putty\.projects\.tartarus\.org/
		$s40 = /putty\.log/
		$s41 = /\\\\\.\\pipe\\putty\-connshare/
		$s42 = /SSHCONNECTION\@putty\.projects\.tartarus\.org\-/
		$s43 = /Eputty/
		$s44 = /\(Gputty w/
		$s45 = /putty\-64bit\-0\.75\-installer\.msi/
		$s46 = /putty\.exH/
		$s47 = /\%s\\putty\_\%lu\_\%llu\.chm/
		$s48 = /\-restrict\_putty\_acl/
		$s49 = /\-restrict\-putty\-acl/
		$s50 = /reencrypt\@putty\.projects\.tartarus\.org/
		$s51 = /reencrypt\-all\@putty\.projects\.tartarus\.org/
		$s52 = /add\-ppk\@putty\.projects\.tartarus\.org/
		$s53 = /list\-extended\@putty\.projects\.tartarus\.org/
		$s54 = /    \<id\>putty\.install\<\/id\>/
		$s55 = /puttygen\.exe/
		$s56 = /putty\.chm/
		$s57 = /puttygen\-pastekey/
		$s58 = /puttygen\-savepriv/
		$s59 = /puttygen\-fingerprint/
		$s60 = /puttygen\-comment/
		$s61 = /puttygen\-conversions/
		$s62 = /puttygen\-save\-ppk\-version/
		$s63 = /pubkey\-puttygen/
		$s64 = /puttygen\-strength/
		$s65 = /puttygen\-save\-passphrase\-hashing/
		$s66 = /puttygen\-generate/
		$s67 = /puttygen\-passphrase/
		$s68 = /puttygen\-keytype/
		$s69 = /puttygen\-load/
		$s70 = /puttygen\-savepub/
		$s71 = /putty\.install v0\.75/
		$s72 = /\*\|\*\|putty\.exe8035/
		$s73 = /\*\|\*\|puttycm10578/
		$s74 = /\*\|\*\|mtputty9908/
		$s75 = /\*\|\*\|puttygen9097/
		$s76 = /\*\|\*\|superputty9395/
		$s77 = /\*\|putty\*\|pputty10432/
		$s78 = /\*\|putty\*\|puitty10476/
		$s79 = /\*\|putty\*\|puttty7773/
		$s80 = /\*\|putty\*\|putty\'9549/
		$s81 = /\*\|putty\*\|puttyu9575/
		$s82 = /\*\|putty\*\|puttyy10003/
		$s83 = /\*\|putty\*\|\[utty10315/
		$s84 = /\*\|putty\*\|outty7343/
		$s85 = /\*\|putty\*\|puttu8881/
		$s86 = /\*\|putty\*\|putyt8978/
		$s87 = /\*\|putty\*\|putyy6661/
		$s88 = /\*\|putty\*\|puuty8019/
		$s89 = /\*\|putty\*\|ptty9605/
		$s90 = /\*\|putty\*\|pytt10212/
		$s91 = /tutmputtyzx/
		$s92 = /  \'putty\'\: COLORS\_16\,/
		$s93 = /putty/
		$s94 = /TERM putty/
		$s95 = /putty \%s\&\%p\:\%u/
		$s96 = /putty\%s\%s/
		$s97 = /putty \%s\@\%s/
	condition:
		77 of ($s*)
}