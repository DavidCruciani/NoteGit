rule 7zip_install {
	meta:
		description = "Auto gene for 7zip"
		author = "David Cruciani"
		date = "2021-06-07"
		versionApp = "19.00"
		uuid = "46e0fdb1-5e03-4b58-afee-c4166de7c27f"
	strings: 
		$s0 = /\*\|\*\|7zip9182/
		$s1 = /chocolatey\.resources\.tools\.7zip\.license\.txt/
		$s2 = /7zip\.install/
		$s3 = /7zip/
		$s4 = /archive\_read\_support\_format\_7zip/
		$s5 = /Can\'t allocate 7zip data/
		$s6 = /archive\_write\_set\_format\_7zip/
		$s7 = /\_archive\_read\_support\_format\_7zip\@4/
		$s8 = /\_archive\_write\_set\_format\_7zip\@4/
		$s9 = /tools\/chocolateyInstall\/tools\/7zip\.license\.txtPK/
		$s10 = /\$packageName \= \'7zip\.install\'/
		$s11 = /tools\/7zip\_x32\.exe /
		$s12 = /    \<id\>7zip\.install\<\/id\>/
		$s13 = /7zip\~/
		$s14 = /7zip\.install v19\.0 \[Approved\]/
		$s15 = /7zip\.install\.nuspec /
		$s16 = /u \/7zip\.hhc/
		$s17 = /r\/7zip\.hhk/
		$s18 = /\*\|\*\|7zip9510/
		$s19 = /7zip\.install v19\.0/
		$s20 = /7zip\.install\.nuspecPK/
		$s21 = /tools\/7zip\_x32\.exePK/
		$s22 = /tools\/7zip\_x64\.exePK/
		$s23 = /tools\/7zip\_x64\.exe /
		$s24 = /7zip\~r/
	condition:
		19 of ($s*)
}