rule googlechrome_fls_uninstall {
	meta:
		description = "Auto gene for chrome"
		author = "David Cruciani"
		date = "2021-06-07"
		versionApp = "91.0.4472.77"
		uuid = "0a6aafe4-3214-43ce-81b6-820d6cdfd1f7"
	strings: 
		$s0 = /chrome\_100\_percent\.pak/
		$s1 = /chrome\_200\_percent\.pak/
		$s2 = /chrome\_installer\.exe/
		$s3 = /com\.microsoft\.defender\.be\.chrome\.json/
		$s4 = /chrome\_shutdown\_ms\.txt/
		$s5 = /googlechromestandaloneenterprise64\.msi/
		$s6 = /chrome\_installer\.log/
		$s7 = /chrome/
		$s8 = /chrome\.browser/
		$s9 = /backstack\-chrome\-breadcrumb\-template\.html/
		$s10 = /backstack\-chrome\-breadcrumb\-vm\.js/
		$s11 = /oobe\-chrome\-footer\-vm\.js/
		$s12 = /close\-chrome\-breadcrumb\-template\.html/
		$s13 = /close\-chrome\-breadcrumb\-vm\.js/
		$s14 = /oobe\-chrome\-breadcrumb\-template\.html/
		$s15 = /oobe\-chrome\-breadcrumb\-vm\.js/
		$s16 = /oobe\-chrome\-contentview\-template\.html/
		$s17 = /oobe\-chrome\-contentview\-vm\.js/
		$s18 = /oobe\-chrome\-footer\-template\.html/
		$s19 = /CHROME\.EXE\-5A1054AF\.pf/
		$s20 = /CHROME\.EXE\-5A1054B0\.pf/
		$s21 = /CHROME\.EXE\-5A1054B1\.pf/
		$s22 = /CHROME\.EXE\-5A1054B6\.pf/
		$s23 = /CHROME\.EXE\-5A1054B7\.pf/
		$s24 = /chrome\.dll/
		$s25 = /chrome\.dll\.sig/
		$s26 = /chrome\.exe\.sig/
		$s27 = /chrome\_elf\.dll/
		$s28 = /chrome\_pwa\_launcher\.exe/
		$s29 = /chrome\.7z/
		$s30 = /chrome\.exe/
		$s31 = /chrome\.VisualElementsManifest\.xml/
		$s32 = /chrome\_proxy\.exe/
	condition:
		25 of ($s*)
}