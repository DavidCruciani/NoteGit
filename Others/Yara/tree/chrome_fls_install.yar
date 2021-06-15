rule chrome_fls_install {
	meta:
		description = "Auto gene for chrome"
		author = "David Cruciani"
		date = "2021-06-14"
		versionApp = "91.0.4472.101"
		uuid = "99bd5288-75a2-4077-953f-7307d09f1c57"
	strings: 
		$s0 = /chrome\.dll/
		$s1 = /chrome\.dll\.sig/
		$s2 = /chrome\.exe\.sig/
		$s3 = /chrome\_100\_percent\.pak/
		$s4 = /chrome\_200\_percent\.pak/
		$s5 = /chrome\_elf\.dll/
		$s6 = /chrome\_pwa\_launcher\.exe/
		$s7 = /chrome\.7z/
		$s8 = /chrome\.exe/
		$s9 = /chrome\.VisualElementsManifest\.xml/
		$s10 = /chrome\_proxy\.exe/
		$s11 = /91\.0\.4472\.101\_chrome\_installer\.exe/
		$s12 = /com\.microsoft\.defender\.be\.chrome\.json/
		$s13 = /chrome\_shutdown\_ms\.txt/
		$s14 = /chrome\_installer\.log/
		$s15 = /chrome/
		$s16 = /chrome\.browser/
		$s17 = /backstack\-chrome\-breadcrumb\-template\.html/
		$s18 = /backstack\-chrome\-breadcrumb\-vm\.js/
		$s19 = /oobe\-chrome\-footer\-vm\.js/
		$s20 = /close\-chrome\-breadcrumb\-template\.html/
		$s21 = /close\-chrome\-breadcrumb\-vm\.js/
		$s22 = /oobe\-chrome\-breadcrumb\-template\.html/
		$s23 = /oobe\-chrome\-breadcrumb\-vm\.js/
		$s24 = /oobe\-chrome\-contentview\-template\.html/
		$s25 = /oobe\-chrome\-contentview\-vm\.js/
		$s26 = /oobe\-chrome\-footer\-template\.html/
		$s27 = /91\.0\.4472\.101\_CHROME\_INSTALLE\-9F87B2D7\.pf/
		$s28 = /CHROME\.EXE\-5A1054AF\.pf/
		$s29 = /CHROME\.EXE\-5A1054B0\.pf/
		$s30 = /CHROME\.EXE\-5A1054B1\.pf/
		$s31 = /CHROME\.EXE\-5A1054B6\.pf/
		$s32 = /CHROME\.EXE\-5A1054B7\.pf/
		$s33 = /CHROME\.EXE\-DE7ED38C\.pf/
		$s34 = /CHROME\.PACKED\.7Z/
	condition:
		27 of ($s*)
}