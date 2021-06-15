rule AcroRd32_uninstall {
	meta:
		description = "Auto gene for AcroRd32"
		author = "David Cruciani"
		date = "2021-06-14"
		versionApp = "21.5.20048.436468"
		uuid = "828a2b21-1282-408e-b2be-a5d08b6cd3a6"
	strings: 
		$s0 = /AcroRd32\.exe/
		$s1 = /AcroRd32\.exe\%/
		$s2 = /\|rdr\|\\acrord32\.dll/
		$s3 = /\|rdr\|\\acrord32\.exe/
		$s4 = /\|rdr\|\\AcroRd32Res\.dll/
		$s5 = /\|tmp\|\\acrord32\_sbx/
		$s6 = /AcroRd32IsBrokerProcess/
		$s7 = /AcroRd32\.exe\'/
		$s8 = /AcroRd32\.exe\$/
		$s9 = /AcroRd32Info\.exeX/
		$s10 = /AcroRd32Info\.exe/
		$s11 = /AcroRd32/
		$s12 = /acrord32\~/
		$s13 = /AcroRd32Exe\.pdb/
		$s14 = /\"\[READER\]AcroRd32\.exe\"\$/
		$s15 = /\"\[READER\]AcroRd32\.exe\" \"\%1\"\$/
		$s16 = /\[READER\]AcroRd32\.dll\\2\$/
		$s17 = /\.pdf\\OpenWithList\\AcroRd32\.exe/
		$s18 = /\[READER\]AcroRd32\.exe\$/
		$s19 = /\.pdfxml\\OpenWithList\\AcroRd32\.exe/
		$s20 = /\[READER\]AcroRd32\.exe\&/
		$s21 = /\[INSTALLDIR\]Reader\\AcroRd32\.exe\&/
		$s22 = /AcroRd32\.exe\&/
		$s23 = /AcroRd32Info\.pdb/
		$s24 = /D\:\\B\\T\\BuildResults\\bin\\Release\\AcroRd32\.pdb/
		$s25 = /AcroRd32\.dll/
		$s26 = /AcroRd32Res\.dll/
		$s27 = /AcroRd32\.pdb/
		$s28 = /D\:\\B\\T\\BuildResults\\bin\\Release\\AcroRd32Info\.pdb/
		$s29 = /AcroRd32\.exek/
		$s30 = /AcroRd32\.exec/
		$s31 = /AcroRd32\.exeb/
		$s32 = /AcroRd32\.exeM/
		$s33 = /AcroRd32\.exe\.928/
		$s34 = /\\AcroRd32\.exe/
		$s35 = /acrord32res\.dll/
		$s36 = /\|rdr\|\\AcroRd32\.dll/
		$s37 = /D\:\\B\\T\\BuildResults\\bin\\Release\\AcroRd32Exe\.pdb/
		$s38 = /\.pdf\\OpenWithList\\AcroRd32\.exep/
		$s39 = /\.pdfxml\\OpenWithList\\AcroRd32\.exep/
	condition:
		31 of ($s*)
}