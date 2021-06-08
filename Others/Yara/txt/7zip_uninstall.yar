rule 7zip_uninstall {
	meta:
		description = "Auto gene for 7zip"
		author = "David Cruciani"
		date = "2021-06-07"
		versionApp = "19.00"
		uuid = "f8fd687c-2679-4693-a425-15cc8747c57d"
	strings: 
		$s0 = /\*\|\*\|7zip9182/
		$s1 = /chocolatey\.resources\.tools\.7zip\.license\.txt/
		$s2 = /7zip/
		$s3 = /archive\_read\_support\_format\_7zip/
		$s4 = /Can\'t allocate 7zip data/
		$s5 = /archive\_write\_set\_format\_7zip/
		$s6 = /\_archive\_read\_support\_format\_7zip\@4/
		$s7 = /\_archive\_write\_set\_format\_7zip\@4/
		$s8 = /tools\/chocolateyInstall\/tools\/7zip\.license\.txtPK/
		$s9 = /7zip\~/
		$s10 = /\$packageName \= \'7zip\.install\'/
		$s11 = /tools\/7zip\_x32\.exe /
		$s12 = /    \<id\>7zip\.install\<\/id\>/
		$s13 = /7zip\.install v19\.0 \[Approved\]/
		$s14 = /7zip\.install\.nuspec /
		$s15 = /u \/7zip\.hhc/
		$s16 = /r\/7zip\.hhk/
		$s17 = /7zip\.install v19\.0/
		$s18 = /\*\|\*\|7zip9510/
		$s19 = /7zip\.install\.nuspecPK/
		$s20 = /tools\/7zip\_x32\.exePK/
		$s21 = /tools\/7zip\_x64\.exePK/
		$s22 = /tools\/7zip\_x64\.exe /
		$s23 = /7zip\~r/
	condition:
		18 of ($s*)
}