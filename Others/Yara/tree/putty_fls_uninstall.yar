rule putty_fls_uninstall {
	meta:
		description = "Auto gene for putty"
		author = "David Cruciani"
		date = "2021-06-07"
		versionApp = "Release 0.75"
		uuid = "49a12033-34ce-498d-88b0-c200c40d9400"
	strings: 
		$s0 = /putty\.install\.0\.75/
		$s1 = /putty\.install/
		$s2 = /putty\.install\.nupkg/
		$s3 = /putty\.install\.nuspec/
		$s4 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_puttygen\_exe/
		$s5 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_putty\_chm/
		$s6 = /PUTTY\.EXE\-7D8FB982\.pf/
		$s7 = /putty\-64bit\-0\.75\-installer\.msi/
		$s8 = /putty\-arm64\-0\.75\-installer\.msi/
		$s9 = /screen\.putty/
		$s10 = /screen\.putty\-256color/
		$s11 = /screen\.putty\-m1/
		$s12 = /screen\.putty\-m1b/
		$s13 = /screen\.putty\-m2/
	condition:
		10 of ($s*)
}