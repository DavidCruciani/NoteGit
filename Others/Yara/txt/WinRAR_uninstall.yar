rule WinRAR_uninstall {
	meta:
		description = "Auto gene for WinRAR"
		author = "David Cruciani"
		date = "2021-06-17"
		versionApp = "6.1.0"
		uuid = "a1fd6a9b-d148-4e8c-94dd-413c43cb42c8"
	strings: 
		$s0 = /WinRAR/
		$s1 = /WinRAR\.lnk/
		$s2 = / WinRAR/
		$s3 = /q  WinRAR\.lnk/
		$s4 = /winrar\.exe\|55dc552369664f2a/
		$s5 = /\*\|\*\|winrar7231/
		$s6 = /Roshal\.WinRAR\.WinRAR/
		$s7 = /WinRAR SFXctures/
		$s8 = /C\%\%Program Files\%WinRAR/
		$s9 = /  name\=\"WinRAR SFX\"/
		$s10 = /winrar\~/
		$s11 = / WinRAR\!\<\/h5\>/
		$s12 = / winrar/
		$s13 = /winrar/
		$s14 = / winrarOAide de/
		$s15 = / WinRARB\*\|/
		$s16 = /O\|winrar/
		$s17 = /\|WinRARB\*\|/
		$s18 = /WinRARra/
		$s19 = /WinRARraH/
		$s20 = /de winrar\~/
		$s21 = /aide de winrar\~/
		$s22 = /  name\=\"WinRAR\"/
		$s23 = /winrar v6\.01 \[Approved\]/
		$s24 = /winrar v6\.01/
		$s25 = /\*\|\*\|winrar7729/
		$s26 = /\*\|winrar\*\|winz7238/
		$s27 = /\*\|winrar\*\|winwar7230/
		$s28 = /\*\|winrar\*\|win rar5709/
		$s29 = /winrar\.exe/
		$s30 = /\$packageSearch \= \"WinRAR\*\"/
		$s31 = /WinRARab/
		$s32 = /WinRAR7/
		$s33 = /WinRAR4\~/
		$s34 = /WinRAR\.ZIP/
		$s35 = /WinRAR32/
		$s36 = /WinRARtV/
		$s37 = /WinRARtt/
		$s38 = /WinRARI\]/
		$s39 = /WinRAR\.REV\|/
		$s40 = /WinRAR archiver/
	condition:
		32 of ($s*)
}