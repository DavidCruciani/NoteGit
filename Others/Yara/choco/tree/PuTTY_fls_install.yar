rule PuTTY_fls_install {
	meta:
		description = "Auto gene for PuTTY"
		author = "David Cruciani"
		date = "2021-07-01"
		versionApp = "Release 0.75"
		uuid = "3bd4fe49-a693-49ef-aa08-7f0cac86b7d0"
	strings: 
		$s0 = /PuTTY/
		$s1 = /putty\.chm/
		$s2 = /putty\.exe/
		$s3 = /puttygen\.exe/
		$s4 = /putty\.install\.0\.75/
		$s5 = /putty\.install/
		$s6 = /putty\.install\.nupkg/
		$s7 = /putty\.install\.nuspec/
		$s8 = /PuTTY \(64\-bit\)/
		$s9 = /PuTTY Manual\.lnk/
		$s10 = /PuTTY Web Site\.lnk/
		$s11 = /PuTTY\.lnk/
		$s12 = /PuTTYgen\.lnk/
		$s13 = /SimonTatham\_PuTTY/
		$s14 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_pageant\_exe/
		$s15 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_psftp\_exe/
		$s16 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_puttygen\_exe/
		$s17 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_putty\_chm/
		$s18 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_website\_url/
		$s19 = /PUTTY\.EXE\-7D8FB982\.pf/
	condition:
		15 of ($s*)
}