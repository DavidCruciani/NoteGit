rule PuTTY_fls_uninstall {
	meta:
		description = "Auto gene for PuTTY"
		author = "David Cruciani"
		date = "2021-07-02"
		versionApp = "Release 0.75"
		uuid = "fc08e98a-f1ce-48df-9b98-7bcffd1e2c39"
	strings: 
		$s0 = /SimonTatham\_PuTTY/
		$s1 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_pageant\_exe/
		$s2 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_psftp\_exe/
		$s3 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_puttygen\_exe/
		$s4 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_putty\_chm/
		$s5 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_website\_url/
		$s6 = /PUTTY\.EXE\-7D8FB982\.pf/
	condition:
		4 of ($s*)
}