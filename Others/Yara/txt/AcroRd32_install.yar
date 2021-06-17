rule AcroRd32_install {
	meta:
		description = "Auto gene for AcroRd32"
		author = "David Cruciani"
		date = "2021-06-17"
		versionApp = "21.5.20048.436468"
		uuid = "2e32c2e5-f3c4-4a56-a8c0-24a338ae8626"
	strings: 
		$s0 = /AcroRd32\.exe/
		$s1 = /\|rdr\|\\acrord32\.dll/
		$s2 = /\|rdr\|\\acrord32\.exe/
		$s3 = /\|rdr\|\\AcroRd32Res\.dll/
		$s4 = /\|tmp\|\\acrord32\_sbx/
		$s5 = /AcroRd32\.exe\'/
		$s6 = /AcroRd32\.exe\$/
		$s7 = /AcroRd32IsBrokerProcess/
		$s8 = /AcroRd32Info\.exeX/
		$s9 = /AcroRd32Info\.exe/
		$s10 = /AcroRd32Exe\.pdb/
		$s11 = /\[READER\]AcroRd32\.exe\$/
		$s12 = /AcroRd32\.dll/
		$s13 = /AcroRd32Res\.dll/
		$s14 = /AcroRd32\.pdb/
		$s15 = /AcroRd32\.exek/
		$s16 = /AcroRd32\.exec/
		$s17 = /AcroRd32\.exeb/
		$s18 = /AcroRd32\.exe\.928/
		$s19 = /\\AcroRd32\.exe/
		$s20 = /acrord32res\.dll/
		$s21 = /\|rdr\|\\AcroRd32\.dll/
		$s22 = /D\:\\B\\T\\BuildResults\\bin\\Release\\AcroRd32Exe\.pdb/
		$s23 = /AcroRd32Info\.pdb/
		$s24 = /\.pdf\\OpenWithList\\AcroRd32\.exep/
		$s25 = /\.pdfxml\\OpenWithList\\AcroRd32\.exep/
		$s26 = /D\:\\B\\T\\BuildResults\\bin\\Release\\AcroRd32\.pdb/
	condition:
		20 of ($s*)
}