rule putty_uninstall {
        meta:
                description = "Auto gene for putty"
                author = "David Cruciani"
                date = "2021-06-28"
                versionApp = "Release 0.75"
                uuid = "69484a4e-6da7-42f2-96a4-21e7f1d3c61f"
        strings:
                $s0 = /SSHCONNECTION\@putty\.projects\.tartarus\.org\-2\.0\-/
                $s1 = /putty\-private\-key\-file\-mac\-key/
                $s2 = /Local\\putty\-connshare\-mutex/
                $s3 = /winadj\@putty\.projects\.tartarus\.org/
                $s4 = /simple\@putty\.projects\.tartarus\.org/
                $s5 = /putty\.log/
                $s6 = /\\\\\.\\pipe\\putty\-connshare/
                $s7 = /SSHCONNECTION\@putty\.projects\.tartarus\.org\-/
                $s8 = /Eputty/
                $s9 = /\(Gputty w/
                $s10 = /puttygen\-pastekey/
                $s11 = /puttygen\-savepriv/
                $s12 = /puttygen\-fingerprint/
                $s13 = /puttygen\-comment/
                $s14 = /puttygen\-conversions/
                $s15 = /puttygen\-save\-ppk\-version/
                $s16 = /pubkey\-puttygen/
                $s17 = /\%s\\putty\_\%lu\_\%llu\.chm/
                $s18 = /puttygen\-strength/
                $s19 = /puttygen\-save\-passphrase\-hashing/
                $s20 = /puttygen\-generate/
                $s21 = /puttygen\-passphrase/
                $s22 = /puttygen\-keytype/
                $s23 = /puttygen\-load/
                $s24 = /puttygen\-savepub/
                $s25 = /putty\.msi/
                $s26 = /putty \%s\&\%p\:\%u/
                $s27 = /putty\%s\%s/
                $s28 = /putty \%s\@\%s/
                $s29 = /puttygen\.exe/
                $s30 = /putty\.chm/
                $s31 = /putty\~/
                $s32 = /puttygen\~/
                $s33 = /putty web site\~/
                $s34 = /putty manual\~/
                $s35 = /putty\.exH/
                $s36 = /\-restrict\_putty\_acl/
                $s37 = /\-restrict\-putty\-acl/
                $s38 = /reencrypt\@putty\.projects\.tartarus\.org/
                $s39 = /reencrypt\-all\@putty\.projects\.tartarus\.org/
                $s40 = /add\-ppk\@putty\.projects\.tartarus\.org/
                $s41 = /list\-extended\@putty\.projects\.tartarus\.org/
        condition:
                32 of ($s*)
}
