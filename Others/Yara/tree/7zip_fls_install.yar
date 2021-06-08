rule 7zip_fls_install {
	meta:
		description = "Auto gene for 7zip"
		author = "David Cruciani"
		date = "2021-06-07"
		versionApp = "19.00"
		uuid = "f112ec1d-037d-42d3-884f-d2383e438965"
	strings: 
		$s0 = /7zip\.install\.19\.0/
		$s1 = /7zip\.install/
		$s2 = /7zip\.install\.nupkg/
		$s3 = /7zip\.install\.nuspec/
		$s4 = /7zip\_x64\.exe\.ignore/
		$s5 = /7zip\.license\.txt/
		$s6 = /7ZIP\_X64\.EXE\-D6595D36\.pf/
		$s7 = /7zip\_x32\.exe/
		$s8 = /7zip\_x64\.exe/
	condition:
		6 of ($s*)
}