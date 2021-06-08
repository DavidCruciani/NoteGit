rule 7zip_fls_uninstall {
	meta:
		description = "Auto gene for 7zip"
		author = "David Cruciani"
		date = "2021-06-07"
		versionApp = "19.00"
		uuid = "d484c052-d99e-4fed-9193-7dc18488573e"
	strings: 
		$s0 = /7zip\.install\.19\.0/
		$s1 = /7zip\.license\.txt/
		$s2 = /7zip\_x32\.exe/
		$s3 = /7zip\_x64\.exe/
		$s4 = /7ZIP\_X64\.EXE\-D6595D36\.pf/
		$s5 = /7zip\_x64\.exe\.ignore/
		$s6 = /7zip\.install\.nupkg/
		$s7 = /7zip\.install\.nuspec/
	condition:
		5 of ($s*)
}