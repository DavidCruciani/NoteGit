rule putty_fls_uninstall {
	meta:
		description = "Auto gene for putty"
		author = "David Cruciani"
		date = "2021-06-11"
		versionApp = "Release 0.75"
		uuid = "60eb18d4-bcf3-4686-aeff-a227003f80ce"
	strings: 
		$s0 = /putty\.chm/
		$s1 = /putty\.exe/
		$s2 = /puttygen\.exe/
		$s3 = /putty\.install\.0\.75/
		$s4 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_puttygen\_exe/
		$s5 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_putty\_chm/
		$s6 = /putty\.install/
		$s7 = /PUTTY\.EXE\-7D8FB982\.pf/
		$s8 = /PUTTY\.EXE\-F8AEBD10\.pf/
		$s9 = /screen\.putty/
		$s10 = /screen\.putty\-256color/
		$s11 = /screen\.putty\-m1/
		$s12 = /screen\.putty\-m1b/
		$s13 = /screen\.putty\-m2/
	condition:
		10 of ($s*)
}