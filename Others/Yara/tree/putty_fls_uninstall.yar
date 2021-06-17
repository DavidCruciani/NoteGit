rule putty_fls_uninstall {
	meta:
		description = "Auto gene for putty"
		author = "David Cruciani"
		date = "2021-06-17"
		versionApp = "Release 0.75"
		uuid = "180b1df5-c076-446f-a7c1-0331132683a5"
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