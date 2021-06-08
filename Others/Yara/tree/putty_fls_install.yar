rule putty_fls_install {
	meta:
		description = "Auto gene for putty"
		author = "David Cruciani"
		date = "2021-06-07"
		versionApp = "Release 0.75"
		uuid = "29ca832d-a0a2-4f5c-999e-0d21ff59397d"
	strings: 
		$s0 = /putty\.chm/
		$s1 = /putty\.exe/
		$s2 = /puttygen\.exe/
		$s3 = /putty\.install\.0\.75/
		$s4 = /putty\.install/
		$s5 = /putty\.install\.nupkg/
		$s6 = /putty\.install\.nuspec/
		$s7 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_puttygen\_exe/
		$s8 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_putty\_chm/
		$s9 = /PUTTY\.EXE\-7D8FB982\.pf/
		$s10 = /screen\.putty/
		$s11 = /screen\.putty\-256color/
		$s12 = /screen\.putty\-m1/
		$s13 = /screen\.putty\-m1b/
		$s14 = /screen\.putty\-m2/
	condition:
		11 of ($s*)
}