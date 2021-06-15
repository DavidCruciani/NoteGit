rule WinRAR_fls_install {
	meta:
		description = "Auto gene for WinRAR"
		author = "David Cruciani"
		date = "2021-06-14"
		versionApp = "6.1.0"
		uuid = "8fe9edd2-cab2-472f-9f60-ad9c072443dd"
	strings: 
		$s0 = /WinRAR/
		$s1 = /winrar\.chm/
		$s2 = /WinRAR\.exe/
		$s3 = /winrar\.lng/
		$s4 = /winrar\.6\.01/
		$s5 = /Aide de WinRAR\.lnk/
		$s6 = /WinRAR\.lnk/
		$s7 = /winrar\_books\[1\]\.png/
		$s8 = /logo\-winrar\[1\]\.gif/
		$s9 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_Rar\_txt/
		$s10 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_WhatsNew\_txt/
		$s11 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_winrar\_chm/
		$s12 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_WinRAR\_exe/
		$s13 = /winrar/
		$s14 = /WINRAR\-X64\-601FR\.EXE\-93E09DD6\.pf/
		$s15 = /WINRAR\.EXE\-00D8F685\.pf/
		$s16 = /WINRAR\.EXE\-94E7D80C\.pf/
	condition:
		12 of ($s*)
}