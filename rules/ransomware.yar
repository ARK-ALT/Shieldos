/*
 * ShieldOS YARA Rules — Ransomware Families
 * WannaCry, Ryuk, Conti, LockBit, BlackCat, Generic families.
 */

rule WannaCry_Ransomware
{
    meta:
        description = "WannaCry / WanaCrypt0r ransomware artifacts"
        author      = "ShieldOS Research"
        severity    = "critical"
        family      = "WannaCry"
    strings:
        $s1  = "WANACRY!"         wide ascii
        $s2  = "tasksche.exe"     wide ascii
        $s3  = ".WNCRY"           wide ascii
        $s4  = "WNcry@2ol7"       wide ascii
        $s5  = "wcry@123"         wide ascii
        $s6  = "@Please_Read_Me@.txt" wide ascii
        $s7  = "WanaDecryptor"    wide ascii
        $cmd = "cmd.exe /c %s"    wide ascii
        $tor = "gx7ekbenv2riucmf.onion" ascii
    condition:
        2 of ($s*) or $tor
}

rule Ryuk_Ransomware
{
    meta:
        description = "Ryuk ransomware indicators"
        severity    = "critical"
        family      = "Ryuk"
    strings:
        $note = "RyukReadMe.txt"              nocase ascii wide
        $ext  = ".RYK"                        wide ascii
        $cmd  = "cmd.exe /c net stop"         wide ascii
        $del  = "shadowcopy delete"           nocase ascii
        $s1   = "RYUK"                        ascii
        $s2   = "No system is safe"           ascii
        $lanman = "lanmanworkstation"         nocase ascii
    condition:
        2 of them
}

rule Conti_Ransomware
{
    meta:
        description = "Conti ransomware indicators"
        severity    = "critical"
        family      = "Conti"
    strings:
        $note1 = "CONTI_README.txt"           nocase ascii wide
        $note2 = "readme.txt"                 nocase ascii wide
        $ext   = ".CONTI"                     ascii wide
        $shad  = "vssadmin Delete Shadows"    nocase ascii
        $svcs  = "net stop"                   ascii
        $s1    = "conti_v"                    ascii nocase
        $email = "@protonmail.com"            ascii
        $tor   = ".onion"                     ascii
    condition:
        ($note1 or $note2) and ($shad or $svcs) or
        ($ext and ($tor or $email))
}

rule LockBit_Ransomware
{
    meta:
        description = "LockBit ransomware family indicators"
        severity    = "critical"
        family      = "LockBit"
    strings:
        $note  = "Restore-My-Files.txt"       nocase ascii wide
        $note2 = "LockBit_Ransomware.hta"     nocase ascii wide
        $ext1  = ".lockbit"                   nocase ascii wide
        $ext2  = ".abcd"                      ascii wide
        $s1    = "LockBit"                    ascii wide
        $cmd1  = "vssadmin resize shadowstorage" nocase ascii
        $cmd2  = "bcdedit /set {default}"     nocase ascii
        $tor   = "lockbit"                    ascii
    condition:
        any of ($note*) or
        any of ($ext*) or
        ($s1 and any of ($cmd*))
}

rule BlackCat_ALPHV_Ransomware
{
    meta:
        description = "BlackCat / ALPHV ransomware indicators"
        severity    = "critical"
        family      = "BlackCat"
    strings:
        $note  = "RECOVER-"                   ascii
        $ext1  = ".blackcat"                  nocase ascii
        $ext2  = ".alphv"                     nocase ascii
        $s1    = "ALPHV"                      ascii
        $s2    = "BlackCat"                   ascii
        $cfg   = "access_token"               ascii
        $rust  = "tokio"                      ascii   // Rust async runtime
    condition:
        any of ($note, $s1, $s2) or
        any of ($ext*) or
        ($cfg and $rust and any of ($ext*))
}

rule Sodinokibi_REvil_Ransomware
{
    meta:
        description = "Sodinokibi / REvil ransomware indicators"
        severity    = "critical"
        family      = "REvil"
    strings:
        $note  = "-readme.txt"                nocase ascii wide
        $s1    = "sodinokibi"                 nocase ascii
        $s2    = "revil"                      nocase ascii
        $ext   = /\.[a-z0-9]{5,10}$/         // random extension
        $cfg   = "pk"                         ascii   // RSA public key field
        $cmd1  = "vssadmin.exe Delete"        nocase ascii
        $tor   = "decoder.re"                 ascii
    condition:
        $s1 or $s2 or $tor or
        ($note and $cmd1)
}

rule Generic_Ransomware_VSS_Deletion
{
    meta:
        description = "Generic ransomware: shadow copy deletion"
        severity    = "critical"
    strings:
        $vss   = "vssadmin"                   nocase ascii wide
        $shad  = "delete shadows"             nocase ascii wide
        $bcd   = "bcdedit"                    nocase ascii wide
        $rec   = "recoveryenabled no"         nocase ascii wide
        $wbm   = "wbadmin delete catalog"     nocase ascii wide
        $svc1  = "net stop vss"               nocase ascii
        $svc2  = "sc delete VSS"              nocase ascii
    condition:
        ($vss and $shad) or
        ($bcd and $rec) or
        $wbm or $svc2
}

rule Generic_Ransomware_Extension_Rename
{
    meta:
        description = "Mass file extension renaming (ransomware behaviour)"
        severity    = "high"
    strings:
        $mv1 = "MoveFile"                     nocase ascii wide
        $mv2 = "MoveFileEx"                   nocase ascii wide
        $mv3 = "os.rename"                    nocase ascii
        $ren = "ren "                         ascii
        $enc_ext1 = ".encrypted"             nocase ascii wide
        $enc_ext2 = ".locked"               nocase ascii wide
        $enc_ext3 = ".enc"                   nocase ascii wide
    condition:
        any of ($mv*) and any of ($enc_ext*)
}

rule Ransomware_Ransom_Note_Dropper
{
    meta:
        description = "Ransomware drops ransom note files"
        severity    = "critical"
    strings:
        $create = "CreateFile"          nocase ascii wide
        $note1  = "HOW TO RECOVER"     nocase ascii wide
        $note2  = "HOW TO DECRYPT"     nocase ascii wide
        $note3  = "DECRYPT INSTRUCTIONS" nocase ascii wide
        $note4  = "YOUR FILES ARE ENCRYPTED" nocase ascii wide
        $note5  = "Pay the ransom"      nocase ascii wide
        $btc    = "bitcoin"             nocase ascii wide
        $xmr    = "monero"             nocase ascii wide
    condition:
        $create and any of ($note*) and any of ($btc, $xmr)
}
