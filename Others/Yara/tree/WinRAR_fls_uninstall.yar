rule WinRAR_fls_uninstall {
	meta:
		description = "Auto gene for WinRAR"
		author = "David Cruciani"
		date = "2021-06-14"
		versionApp = "6.1.0"
		uuid = "10271b6f-264d-4024-bf24-5d8b8fc5f82e"
	strings: 
		$s0 = /winrar\.6\.01/
		$s1 = /winrar\_books\[1\]\.png/
		$s2 = /logo\-winrar\[1\]\.gif/
		$s3 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_Rar\_txt/
		$s4 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_WhatsNew\_txt/
		$s5 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_winrar\_chm/
		$s6 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_WinRAR\_exe/
		$s7 = /winrar/
		$s8 = /WinRAR/
		$s9 = /WINRAR\-X64\-601FR\.EXE\-93E09DD6\.pf/
		$s10 = /WINRAR\.EXE\-00D8F685\.pf/
		$s11 = /WINRAR\.EXE\-94E7D80C\.pf/
	condition:
		8 of ($s*)
}