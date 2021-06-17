rule chrome_fls_install {
	meta:
		description = "Auto gene for chrome"
		author = "David Cruciani"
		date = "2021-06-17"
		versionApp = "91.0.4472.106"
		uuid = "e908b24b-3b98-45b2-845e-9b1422f07f26"
	strings: 
		$s0 = /chrome\_100\_percent\.pak/
		$s1 = /chrome\_200\_percent\.pak/
		$s2 = /com\.microsoft\.defender\.be\.chrome\.json/
		$s3 = /chrome\_installer\.log/
		$s4 = /chrome/
		$s5 = /chrome\.browser/
		$s6 = /backstack\-chrome\-breadcrumb\-template\.html/
		$s7 = /backstack\-chrome\-breadcrumb\-vm\.js/
		$s8 = /close\-chrome\-breadcrumb\-template\.html/
		$s9 = /close\-chrome\-breadcrumb\-vm\.js/
		$s10 = /oobe\-chrome\-breadcrumb\-template\.html/
		$s11 = /oobe\-chrome\-breadcrumb\-vm\.js/
		$s12 = /oobe\-chrome\-contentview\-template\.html/
		$s13 = /oobe\-chrome\-contentview\-vm\.js/
		$s14 = /oobe\-chrome\-footer\-template\.html/
		$s15 = /oobe\-chrome\-footer\-vm\.js/
		$s16 = /91\.0\.4472\.101\_CHROME\_INSTALLE\-9F87B2D7\.pf/
		$s17 = /CHROME\.EXE\-5A1054AF\.pf/
		$s18 = /CHROME\.EXE\-5A1054B0\.pf/
		$s19 = /CHROME\.EXE\-5A1054B1\.pf/
		$s20 = /CHROME\.EXE\-5A1054B6\.pf/
		$s21 = /CHROME\.EXE\-5A1054B7\.pf/
		$s22 = /CHROME\.EXE\-DE7ED38C\.pf/
		$s23 = /chrome\-ext\-2x\.png/
		$s24 = /chrome\-ext\.png/
	condition:
		19 of ($s*)
}