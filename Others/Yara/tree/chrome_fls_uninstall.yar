rule chrome_fls_uninstall {
	meta:
		description = "Auto gene for chrome"
		author = "David Cruciani"
		date = "2021-06-14"
		versionApp = "91.0.4472.101"
		uuid = "9b31ad3a-2539-4a9b-ba3e-0ee4bab901c3"
	strings: 
		$s0 = /chrome\_100\_percent\.pak/
		$s1 = /chrome\_200\_percent\.pak/
		$s2 = /91\.0\.4472\.101\_chrome\_installer\.exe/
		$s3 = /com\.microsoft\.defender\.be\.chrome\.json/
		$s4 = /chrome\_installer\.log/
		$s5 = /chrome/
		$s6 = /chrome\.browser/
		$s7 = /backstack\-chrome\-breadcrumb\-template\.html/
		$s8 = /backstack\-chrome\-breadcrumb\-vm\.js/
		$s9 = /close\-chrome\-breadcrumb\-template\.html/
		$s10 = /close\-chrome\-breadcrumb\-vm\.js/
		$s11 = /oobe\-chrome\-breadcrumb\-template\.html/
		$s12 = /oobe\-chrome\-breadcrumb\-vm\.js/
		$s13 = /oobe\-chrome\-contentview\-template\.html/
		$s14 = /oobe\-chrome\-contentview\-vm\.js/
		$s15 = /oobe\-chrome\-footer\-template\.html/
		$s16 = /oobe\-chrome\-footer\-vm\.js/
		$s17 = /91\.0\.4472\.101\_CHROME\_INSTALLE\-9F87B2D7\.pf/
		$s18 = /CHROME\.EXE\-5A1054AF\.pf/
		$s19 = /CHROME\.EXE\-5A1054B0\.pf/
		$s20 = /CHROME\.EXE\-5A1054B1\.pf/
		$s21 = /CHROME\.EXE\-5A1054B6\.pf/
		$s22 = /CHROME\.EXE\-5A1054B7\.pf/
		$s23 = /CHROME\.EXE\-DE7ED38C\.pf/
	condition:
		18 of ($s*)
}