rule PuTTY_fls_install {
	meta:
		description = "Auto gene for PuTTY"
		author = "David Cruciani"
		date = "2021-06-30"
		versionApp = "Release 0.75"
		uuid = "78055541-302b-43cc-b457-083222ca4bb0"
	strings: 
		$s0 = /putty/
		$s1 = /putty\.chm/
		$s2 = /putty\.exe/
		$s3 = /puttygen\.exe/
		$s4 = /putty \(64\-bit\)/
		$s5 = /putty manual\.lnk/
		$s6 = /putty web site\.lnk/
		$s7 = /putty\.lnk/
		$s8 = /puttygen\.lnk/
		$s9 = /simontatham\_putty/
		$s10 = /\{6d809377\-6af0\-444b\-8957\-a3773f02200e\}\_putty\_pageant\_exe/
		$s11 = /\{6d809377\-6af0\-444b\-8957\-a3773f02200e\}\_putty\_psftp\_exe/
		$s12 = /\{6d809377\-6af0\-444b\-8957\-a3773f02200e\}\_putty\_puttygen\_exe/
		$s13 = /\{6d809377\-6af0\-444b\-8957\-a3773f02200e\}\_putty\_putty\_chm/
		$s14 = /\{6d809377\-6af0\-444b\-8957\-a3773f02200e\}\_putty\_website\_url/
		$s15 = /putty\.exe\-7d8fb982\.pf/
	condition:
		12 of ($s*)
}