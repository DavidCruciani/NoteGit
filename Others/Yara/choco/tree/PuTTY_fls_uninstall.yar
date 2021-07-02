rule PuTTY_fls_uninstall {
	meta:
		description = "Auto gene for PuTTY"
		author = "David Cruciani"
		date = "2021-07-01"
		versionApp = "Release 0.75"
		uuid = "dd700c1b-1d4e-4c09-8268-3683804e1f5b"
	strings: 
		$s0 = /putty\.install\.0\.75/
		$s1 = /SimonTatham\_PuTTY/
		$s2 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_pageant\_exe/
		$s3 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_psftp\_exe/
		$s4 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_puttygen\_exe/
		$s5 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_putty\_chm/
		$s6 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_website\_url/
		$s7 = /putty\.install/
		$s8 = /putty\-64bit\-0\.75\-installer\.msi/
		$s9 = /putty\-arm64\-0\.75\-installer\.msi/
		$s10 = /PUTTY\.EXE\-7D8FB982\.pf/
	condition:
		8 of ($s*)
}