rule putty_fls_uninstall {
        meta:
                description = "Auto gene for putty"
                author = "David Cruciani"
                date = "2021-06-29"
                versionApp = "Release 0.75"
                uuid = "3e3ddf37-34a7-4d73-8d52-e3b741fb46d7"
        strings:
                $s0 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_puttygen\_exe/
                $s1 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_putty\_chm/
                $s2 = /PUTTY\.EXE\-7D8FB982\.pf/
        condition:
                1 of ($s*)
}
