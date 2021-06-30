rule putty_fls_install {
        meta:
                description = "Auto gene for putty"
                author = "David Cruciani"
                date = "2021-06-28"
                versionApp = "Release 0.75"
                uuid = "3516f104-646d-4d41-ac65-033e8c6bc699"
        strings:
                $s0 = /putty\.chm/
                $s1 = /putty\.exe/
                $s2 = /puttygen\.exe/
                $s3 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_puttygen\_exe/
                $s4 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_putty\_chm/
        condition:
                3 of ($s*)
}
