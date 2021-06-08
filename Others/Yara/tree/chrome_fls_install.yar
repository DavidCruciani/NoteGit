rule googlechrome_fls_install {
	meta:
		description = "Auto gene for chrome"
		author = "David Cruciani"
		date = "2021-06-07"
		versionApp = "91.0.4472.77"
		uuid = "14eabca7-fc4e-448c-ad69-6abb91a64b4a"
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
		$s11 = /chrome\_installer\.exe/
		$s12 = /com\.microsoft\.defender\.be\.chrome\.json/
		$s13 = /chrome\_shutdown\_ms\.txt/
		$s14 = /googlechromestandaloneenterprise64\.msi/
		$s15 = /chrome\_installer\.log/
		$s16 = /chrome/
		$s17 = /chrome\.browser/
		$s18 = /backstack\-chrome\-breadcrumb\-template\.html/
		$s19 = /backstack\-chrome\-breadcrumb\-vm\.js/
		$s20 = /oobe\-chrome\-footer\-vm\.js/
		$s21 = /close\-chrome\-breadcrumb\-template\.html/
		$s22 = /close\-chrome\-breadcrumb\-vm\.js/
		$s23 = /oobe\-chrome\-breadcrumb\-template\.html/
		$s24 = /oobe\-chrome\-breadcrumb\-vm\.js/
		$s25 = /oobe\-chrome\-contentview\-template\.html/
		$s26 = /oobe\-chrome\-contentview\-vm\.js/
		$s27 = /oobe\-chrome\-footer\-template\.html/
		$s28 = /CHROME\.EXE\-5A1054AF\.pf/
		$s29 = /CHROME\.EXE\-5A1054B0\.pf/
		$s30 = /CHROME\.EXE\-5A1054B1\.pf/
		$s31 = /CHROME\.EXE\-5A1054B6\.pf/
		$s32 = /CHROME\.EXE\-5A1054B7\.pf/
	condition:
		25 of ($s*)
}