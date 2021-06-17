rule AcroRd32_fls_install {
	meta:
		description = "Auto gene for AcroRd32"
		author = "David Cruciani"
		date = "2021-06-17"
		versionApp = "21.5.20048.436468"
		uuid = "0f91fd45-22de-429b-9bcb-709231c58b2b"
	strings: 
		$s0 = /\{7C5A40EF\-A0FB\-4BFC\-874A\-C0F2E0B9FA8E\}\_Adobe\_Acrobat Reader DC\_Reader\_AcroRd32\_exe/
		$s1 = /acrord32\_sbx/
		$s2 = /acrord32\_super\_sbx/
		$s3 = /ACRORD32\.EXE\-ACF2947D\.pf/
		$s4 = /ACRORD32\.EXE\-ACF2947E\.pf/
	condition:
		3 of ($s*)
}