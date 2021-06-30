rule putty_uninstall {                                                                                                                                                                                                               [0/1928]
        meta:
                description = "Auto gene for putty"
                author = "David Cruciani"
                date = "2021-06-29"
                versionApp = "Release 0.75"
                uuid = "9a43bdb5-74ed-4870-8f0b-dce7d6777089"
        strings:
                $s0 = /putty\.exe\|a07396d107f47123urce/
                $s1 = /puttygen\.exe\|a8e024fc7459f5f3/
                $s2 = /simontatham\.puttywindows\_win32\`/
                $s3 = /simontatham\.puttywindows\_win32\;/
                $s4 = /simontatham\.puttypackageid\`/
                $s5 = /Cpackageidsimontatham\.puttya/
                $s6 = /Cwindows\_win32simontatham\.puttya/
                $s7 = /\#windows\_win32simontatham\.puttya/
                $s8 = /putty\.msi/
                $s9 = /Eputty/
                $s10 = /\(Gputty w/
                $s11 = /putty\~/
                $s12 = /puttygen\~/
                $s13 = /putty web site\~/
                $s14 = /putty manual\~/
                $s15 = /SSHCONNECTION\@putty\.projects\.tartarus\.org\-2\.0\-/
                $s16 = /putty\-private\-key\-file\-mac\-key/
                $s17 = /Local\\putty\-connshare\-mutex/
                $s18 = /putty \%s\&\%p\:\%u/
                $s19 = /putty\%s\%s/
                $s20 = /putty \%s\@\%s/
                $s21 = /\%s\\putty\_\%lu\_\%llu\.chm/
                $s22 = /winadj\@putty\.projects\.tartarus\.org/
                $s23 = /simple\@putty\.projects\.tartarus\.org/
                $s24 = /putty\.log/
                $s25 = /\\\\\.\\pipe\\putty\-connshare/
                $s26 = /SSHCONNECTION\@putty\.projects\.tartarus\.org\-/
                $s27 = /puttygen\.exe/
                $s28 = /putty\.chm/
                $s29 = /puttygen\-pastekey/
                $s30 = /puttygen\-savepriv/
                $s31 = /puttygen\-fingerprint/
                $s32 = /puttygen\-comment/
                $s33 = /puttygen\-conversions/
                $s34 = /puttygen\-save\-ppk\-version/
                $s35 = /pubkey\-puttygen/
                $s36 = /puttygen\-strength/
                $s37 = /puttygen\-save\-passphrase\-hashing/
                $s38 = /puttygen\-generate/
                $s39 = /puttygen\-passphrase/
                $s40 = /puttygen\-keytype/
                $s41 = /puttygen\-load/
                $s42 = /puttygen\-savepub/
                $s43 = /putty\.exH/
                $s44 = /\-restrict\_putty\_acl/
                $s45 = /\-restrict\-putty\-acl/
                $s46 = /reencrypt\@putty\.projects\.tartarus\.org/
                $s47 = /reencrypt\-all\@putty\.projects\.tartarus\.org/
                $s48 = /add\-ppk\@putty\.projects\.tartarus\.org/
                $s49 = /list\-extended\@putty\.projects\.tartarus\.org/
        condition:
                39 of ($s*)
}
