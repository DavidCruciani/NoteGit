rule 7zip_exe {
	meta:
		description = "Auto gene for 7z"
		author = "David Cruciani"
		date = "2021-06-03"
		versionApp = "19.00"
		uuid = "ca352c3c-c46d-11eb-a4f3-b5f146dd4446"
	strings: 
		$h = {4300 6f00 6d00 7000 6100 6e00 7900 4e00 
6100 6d00 6500 0000 0000 4900 6700 6f00 
7200 2000 5000 6100 7600 6c00 6f00 7600 
0000 4400 0e00 0100 4600 6900 6c00 6500 
4400 6500 7300 6300 7200 6900 7000 7400 
6900 6f00 6e00 0000 0000 3700 2d00 5a00 
6900 7000 2000 4300 6f00 6e00 7300 6f00 
6c00 6500 0000                          
}
	condition:
		$h
}