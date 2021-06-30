rule putty_fls_install {
        meta:
                description = "Auto gene for putty"
                author = "David Cruciani"
                date = "2021-06-29"
                versionApp = "Release 0.75"
                uuid = "6bb96509-b302-4188-80e7-4b6229d9f560"
        strings:
                $s0 = /putty\.chm/
                $s1 = /putty\.exe/
                $s2 = /puttygen\.exe/
                $s3 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_puttygen\_exe/
                $s4 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_putty\_chm/
                $s5 = /PUTTY\.EXE\-7D8FB982\.pf/
        condition:
                4 of ($s*)
}
