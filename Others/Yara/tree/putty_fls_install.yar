rule putty_fls_install {
	meta:
		description = "Auto gene for putty"
		author = "David Cruciani"
		date = "2021-06-17"
		versionApp = "Release 0.75"
		uuid = "db0ea9a1-bb0b-44db-ad5e-a34397373cfa"
	strings: 
		$s0 = /putty\.install\.0\.75/
		$s1 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_puttygen\_exe/
		$s2 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_putty\_chm/
		$s3 = /putty\.install/
		$s4 = /PUTTY\.EXE\-7D8FB982\.pf/
		$s5 = /PUTTY\.EXE\-F8AEBD10\.pf/
	condition:
		4 of ($s*)
}