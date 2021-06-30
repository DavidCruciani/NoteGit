rule putty_install {                                                                                                                                                                                                               [303/1928]
        meta:
                description = "Auto gene for putty"
                author = "David Cruciani"
                date = "2021-06-28"
                versionApp = "Release 0.75"
                uuid = "2393bee3-f369-4b1f-a633-3f5ae8732ac6"
        strings:
                $s0 = /SSHCONNECTION\@putty\.projects\.tartarus\.org\-2\.0\-/
                $s1 = /putty\-private\-key\-file\-mac\-key/
                $s2 = /Local\\putty\-connshare\-mutex/
                $s3 = /winadj\@putty\.projects\.tartarus\.org/
                $s4 = /simple\@putty\.projects\.tartarus\.org/
                $s5 = /putty\.log/
                $s6 = /\\\\\.\\pipe\\putty\-connshare/
                $s7 = /SSHCONNECTION\@putty\.projects\.tartarus\.org\-/
                $s8 = /putty\.exe/
                $s9 = /Eputty/
                $s10 = /\(Gputty w/
                $s11 = /puttygen\-pastekey/
                $s12 = /puttygen\-savepriv/
                $s13 = /puttygen\-fingerprint/
                $s14 = /puttygen\-comment/
                $s15 = /puttygen\-conversions/
                $s16 = /puttygen\-save\-ppk\-version/
                $s17 = /pubkey\-puttygen/
                $s18 = /\%s\\putty\_\%lu\_\%llu\.chm/
                $s19 = /puttygen\-strength/
                $s20 = /puttygen\-save\-passphrase\-hashing/
                $s21 = /puttygen\-generate/
                $s22 = /puttygen\-passphrase/
                $s23 = /puttygen\-keytype/
                $s24 = /puttygen\-load/
                $s25 = /puttygen\-savepub/
                $s26 = /putty \%s\&\%p\:\%u/
                $s27 = /putty\%s\%s/
                $s28 = /putty \%s\@\%s/
                $s29 = /putty\~/
                $s30 = /puttygen\~/
                $s31 = /putty web site\~/
                $s32 = /putty manual\~/
                $s33 = /putty\.msi/
                $s34 = /puttygen\.exe/
                $s35 = /putty\.chm/
                $s36 = /\/faq\-putty\-org\.html/
                $s37 = /\/faq\-puttyputty\.html/
                $s38 = /\/faq\-sillyputty\.html/
                $s39 = /\/pubkey\-puttygen\.html/
                $s40 = /\/puttygen\-comment\.html/
                $s41 = /\/puttygen\-conversions\.html/
                $s42 = /\/puttygen\-fingerprint\.html/
                $s43 = /\/puttygen\-generate\.html/
                $s44 = /\/puttygen\-generating\.html/
                $s45 = /\/puttygen\-keytype\.html/
                $s46 = /\/puttygen\-load\.html/
                $s47 = /\/puttygen\-passphrase\.html/
                $s48 = /\/puttygen\-pastekey\.html/
                $s49 = /\/puttygen\-primes\.html/
                $s50 = /\/puttygen\-save\-params\.html/
                $s51 = /\\\&\/puttygen\-save\-passphrase\-hashing\.html/
                $s52 = /\/puttygen\-save\-ppk\-version\.html/
                $s53 = /\/puttygen\-savepriv\.html/
		$s54 = /\/puttygen\-savepub\.html/
                $s55 = /\/puttygen\-strength\.html/
                $s56 = /putty\.exH/
                $s57 = /\-restrict\_putty\_acl/
                $s58 = /\-restrict\-putty\-acl/
                $s59 = /reencrypt\@putty\.projects\.tartarus\.org/
                $s60 = /reencrypt\-all\@putty\.projects\.tartarus\.org/
                $s61 = /add\-ppk\@putty\.projects\.tartarus\.org/
                $s62 = /list\-extended\@putty\.projects\.tartarus\.org/
        condition:
                49 of ($s*)
}
