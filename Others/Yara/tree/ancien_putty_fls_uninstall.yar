rule putty_fls_uninstall {
        meta:
                description = "Auto gene for putty"
                author = "David Cruciani"
                date = "2021-06-28"
                versionApp = "Release 0.75"
                uuid = "8021be3d-186d-4993-b30c-ed81788ddfb4"
        strings:
                $s0 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_puttygen\_exe/
                $s1 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_putty\_chm/
        condition:
                0 of ($s*)
}
