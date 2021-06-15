rule AcroRd32_fls_install {
	meta:
		description = "Auto gene for AcroRd32"
		author = "David Cruciani"
		date = "2021-06-14"
		versionApp = "21.5.20048.436468"
		uuid = "cc798ad0-d06f-4403-bd38-c853b17880cd"
	strings: 
		$s0 = /AcroRd32\.dll/
		$s1 = /AcroRd32\.exe/
		$s2 = /AcroRd32Info\.exe/
		$s3 = /AcroRd32Res\.dll/
		$s4 = /\{7C5A40EF\-A0FB\-4BFC\-874A\-C0F2E0B9FA8E\}\_Adobe\_Acrobat Reader DC\_Reader\_AcroRd32\_exe/
		$s5 = /acrord32\_sbx/
		$s6 = /acrord32\_super\_sbx/
		$s7 = /acrord32res\.dll/
		$s8 = /ACRORD32\.EXE\-ACF2947D\.pf/
		$s9 = /ACRORD32\.EXE\-ACF2947E\.pf/
	condition:
		7 of ($s*)
}