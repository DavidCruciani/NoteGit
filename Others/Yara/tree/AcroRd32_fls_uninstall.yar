rule AcroRd32_fls_uninstall {
	meta:
		description = "Auto gene for AcroRd32"
		author = "David Cruciani"
		date = "2021-06-14"
		versionApp = "21.5.20048.436468"
		uuid = "05ef7586-b8de-469f-848a-cd841a74966b"
	strings: 
		$s0 = /\{7C5A40EF\-A0FB\-4BFC\-874A\-C0F2E0B9FA8E\}\_Adobe\_Acrobat Reader DC\_Reader\_AcroRd32\_exe/
		$s1 = /acrord32\_sbx/
		$s2 = /acrord32\_super\_sbx/
		$s3 = /ACRORD32\.EXE\-ACF2947D\.pf/
		$s4 = /ACRORD32\.EXE\-ACF2947E\.pf/
	condition:
		3 of ($s*)
}