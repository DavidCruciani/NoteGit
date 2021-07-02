rule PuTTY_fls_install {
	meta:
		description = "Auto gene for PuTTY"
		author = "David Cruciani"
		date = "2021-07-02"
		versionApp = "Release 0.75"
		uuid = "3db4149c-de28-4c0b-b857-db9f2bd7706a"
	strings: 
		$s0 = /PUTTY\.EXE\-7D8FB982\.pf/
	condition:
		0 of ($s*)
}