rule PuTTY_fls_uninstall {
	meta:
		description = "Auto gene for PuTTY"
		author = "David Cruciani"
		date = "2021-06-30"
		versionApp = "Release 0.75"
		uuid = "bae1a295-743c-412d-b9b0-22fadc16c5f1"
	strings: 
		$s0 = /simontatham\_putty/
		$s1 = /\{6d809377\-6af0\-444b\-8957\-a3773f02200e\}\_putty\_pageant\_exe/
		$s2 = /\{6d809377\-6af0\-444b\-8957\-a3773f02200e\}\_putty\_psftp\_exe/
		$s3 = /\{6d809377\-6af0\-444b\-8957\-a3773f02200e\}\_putty\_puttygen\_exe/
		$s4 = /\{6d809377\-6af0\-444b\-8957\-a3773f02200e\}\_putty\_putty\_chm/
		$s5 = /\{6d809377\-6af0\-444b\-8957\-a3773f02200e\}\_putty\_website\_url/
		$s6 = /putty\.exe\-7d8fb982\.pf/
	condition:
		4 of ($s*)
}