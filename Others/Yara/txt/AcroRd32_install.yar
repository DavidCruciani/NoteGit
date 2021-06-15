rule AcroRd32_install {
	meta:
		description = "Auto gene for AcroRd32"
		author = "David Cruciani"
		date = "2021-06-14"
		versionApp = "21.5.20048.436468"
		uuid = "98584386-a1e3-4bc7-83da-462daceb4272"
	strings: 
		$s0 = /AcroRd32\.exe/
		$s1 = /\|rdr\|\\acrord32\.dll/
		$s2 = /\|rdr\|\\acrord32\.exe/
		$s3 = /\|rdr\|\\AcroRd32Res\.dll/
		$s4 = /\|tmp\|\\acrord32\_sbx/
		$s5 = /AcroRd32IsBrokerProcess/
		$s6 = /AcroRd32\.exe\'/
		$s7 = /AcroRd32\.exe\$/
		$s8 = /\.pdf\\OpenWithList\\AcroRd32\.exe/
		$s9 = /\.pdfxml\\OpenWithList\\AcroRd32\.exe/
		$s10 = /AcroRd32\.exe\%/
		$s11 = /AcroRd32\.exek/
		$s12 = /AcroRd32\.exec/
		$s13 = /AcroRd32\.exeb/
		$s14 = /AcroRd32\.exeM/
		$s15 = /AcroRd32\.exe\.928/
		$s16 = /AcroRd32Info\.exe/
		$s17 = /AcroRd32/
		$s18 = /acrord32\~/
		$s19 = /AcroRd32Exe\.pdb/
		$s20 = /AcroRd32Info\.pdb/
		$s21 = /D\:\\B\\T\\BuildResults\\bin\\Release\\AcroRd32\.pdb/
		$s22 = /AcroRd32\.dll/
		$s23 = /AcroRd32\.pdb/
		$s24 = /D\:\\B\\T\\BuildResults\\bin\\Release\\AcroRd32Info\.pdb/
		$s25 = /\\AcroRd32\.exe/
		$s26 = /acrord32res\.dll/
		$s27 = /\|rdr\|\\AcroRd32\.dll/
		$s28 = /D\:\\B\\T\\BuildResults\\bin\\Release\\AcroRd32Exe\.pdb/
	condition:
		22 of ($s*)
}