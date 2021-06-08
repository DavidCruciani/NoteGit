rule vlc_fls_install {
	meta:
		description = "Auto gene for vlc"
		author = "David Cruciani"
		date = "2021-06-07"
		versionApp = "3,0,14,0"
		uuid = "80ddfbd7-6221-4b58-b715-ea27f020ab58"
	strings: 
		$s0 = /VLC/
		$s1 = /axvlc\.dll/
		$s2 = /libvlc\.dll/
		$s3 = /libvlccore\.dll/
		$s4 = /vlc\.mo/
		$s5 = /vlc\-48\.png/
		$s6 = /vlc16x16\.png/
		$s7 = /npvlc\.dll/
		$s8 = /vlc\-cache\-gen\.exe/
		$s9 = /vlc\.exe/
		$s10 = /vlc\.3\.0\.14/
		$s11 = /vlc/
		$s12 = /vlc\-3\.0\.14\-win64\_x64\.exe\.ignore/
		$s13 = /vlc\.nupkg/
		$s14 = /vlc\.nuspec/
		$s15 = /VLC media player \- reset preferences and cache files\.lnk/
		$s16 = /VLC media player skinned\.lnk/
		$s17 = /VLC media player\.lnk/
		$s18 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_VideoLAN\_VLC\_Documentation\_url/
		$s19 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_VideoLAN\_VLC\_NEWS\_txt/
		$s20 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_VideoLAN\_VLC\_VideoLAN Website\_url/
		$s21 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_VideoLAN\_VLC\_vlc\_exe/
		$s22 = /VLC\.EXE\-A11F73EE\.pf/
		$s23 = /VLC\-3\.0\.14\-WIN64\_X64\.EXE\-D811B249\.pf/
		$s24 = /VLC\-CACHE\-GEN\.EXE\-4CD0B4D6\.pf/
	condition:
		19 of ($s*)
}