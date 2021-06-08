rule vlc_fls_uninstall {
	meta:
		description = "Auto gene for vlc"
		author = "David Cruciani"
		date = "2021-06-07"
		versionApp = "3,0,14,0"
		uuid = "0f170920-c5be-46a7-bc1a-4bb8e3cc3ae4"
	strings: 
		$s0 = /vlc\.3\.0\.14/
		$s1 = /vlc/
		$s2 = /vlc\.nupkg/
		$s3 = /vlc\-3\.0\.14\-win64\_x64\.exe\.ignore/
		$s4 = /VLC media player \- reset preferences and cache files\.lnk/
		$s5 = /VLC media player skinned\.lnk/
		$s6 = /VLC media player\.lnk/
		$s7 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_VideoLAN\_VLC\_Documentation\_url/
		$s8 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_VideoLAN\_VLC\_NEWS\_txt/
		$s9 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_VideoLAN\_VLC\_VideoLAN Website\_url/
		$s10 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_VideoLAN\_VLC\_vlc\_exe/
		$s11 = /vlc\-3\.0\.14\-win32\_x32\.exe/
		$s12 = /vlc\-3\.0\.14\-win64\_x64\.exe/
		$s13 = /VLC\.EXE\-A11F73EE\.pf/
		$s14 = /VLC\-3\.0\.14\-WIN64\_X64\.EXE\-D811B249\.pf/
		$s15 = /VLC\-CACHE\-GEN\.EXE\-4CD0B4D6\.pf/
		$s16 = /vlc\.nuspec/
		$s17 = /vlc\.mo/
		$s18 = /vlc\-48\.png/
		$s19 = /vlc16x16\.png/
	condition:
		15 of ($s*)
}