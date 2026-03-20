/*
 * ShieldOS YARA Rules — PUPs (Potentially Unwanted Programs)
 * Covers: adware, bundled installers, browser hijackers, riskware.
 */

rule PUP_Adware_Generic
{
    meta:
        description = "Generic adware / ad-injection indicators"
        severity    = "low"
    strings:
        $s1 = "adware"          nocase ascii
        $s2 = "ad-supported"    nocase ascii
        $s3 = "ShowAds"         nocase ascii wide
        $s4 = "inject_ad"       nocase ascii
        $s5 = "BrowserHelper"   nocase ascii wide
    condition:
        2 of them
}

rule PUP_Browser_Hijacker
{
    meta:
        description = "Browser hijacker — modifies homepage / search engine"
        severity    = "medium"
    strings:
        $hk1 = "HKCU\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" ascii wide
        $hk2 = "HKLM\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" ascii wide
        $hk3 = "user_pref(\"browser.startup.homepage\"" ascii
        $hk4 = "HKCU\\Software\\Google\\Chrome\\PreferenceMACs" ascii wide
        $set  = "RegSetValueEx" nocase ascii wide
    condition:
        any of ($hk*) and $set
}

rule PUP_Bundled_Installer_OpenCandy
{
    meta:
        description = "OpenCandy / bundled installer SDK"
        severity    = "low"
    strings:
        $s1 = "OpenCandy"       nocase ascii wide
        $s2 = "OcSetupHlp.dll" nocase ascii wide
        $s3 = "Candid.dll"      nocase ascii
    condition:
        any of them
}

rule PUP_Fake_Antivirus_Scareware
{
    meta:
        description = "Fake antivirus / scareware indicators"
        severity    = "high"
    strings:
        $s1 = "Your computer is infected" nocase ascii wide
        $s2 = "Scan Now"                  nocase ascii wide
        $s3 = "Activate Full Protection"  nocase ascii wide
        $s4 = "Viruses Detected"          nocase ascii wide
        $s5 = "Purchase License"          nocase ascii wide
        $s6 = "Total Security"            nocase ascii wide
    condition:
        3 of them
}

rule PUP_Cryptominer_Browser
{
    meta:
        description = "Browser-based cryptominer (Coinhive / similar)"
        severity    = "medium"
    strings:
        $ch1 = "coinhive.min.js"    nocase ascii
        $ch2 = "coinhive.com"       nocase ascii
        $ch3 = "CoinHive.Miner"     nocase ascii
        $jm1 = "jsecoin"            nocase ascii
        $xmr = "stratum+tcp://"     ascii
        $wasm= "WebAssembly"        ascii
    condition:
        any of ($ch*) or $jm1 or ($xmr and $wasm)
}

rule PUP_Toolbar_Installer
{
    meta:
        description = "Unwanted browser toolbar installer"
        severity    = "low"
    strings:
        $s1 = "toolbar"             nocase ascii wide
        $s2 = "BHO"                 ascii wide   // Browser Helper Object
        $s3 = "SearchScope"         nocase ascii wide
        $s4 = "DefaultSearchURL"    nocase ascii wide
        $s5 = "NewTabURL"           nocase ascii wide
    condition:
        $s1 and 2 of ($s2, $s3, $s4, $s5)
}

rule PUP_Remote_Admin_Tool_Legitimate
{
    meta:
        description = "Legitimate but potentially abused remote admin tools"
        severity    = "low"
    strings:
        $s1 = "TeamViewer"          nocase ascii wide
        $s2 = "AnyDesk"            nocase ascii wide
        $s3 = "Ammyy Admin"         nocase ascii wide
        $s4 = "NetSupport"          nocase ascii wide
        $s5 = "ScreenConnect"       nocase ascii wide
    condition:
        any of them
}

rule PUP_Spyware_Activity_Monitor
{
    meta:
        description = "Activity monitoring / stalkerware indicators"
        severity    = "high"
    strings:
        $s1 = "keylogger"           nocase ascii wide
        $s2 = "activity monitor"    nocase ascii wide
        $s3 = "track keystrokes"    nocase ascii wide
        $s4 = "screenshot"          nocase ascii wide
        $s5 = "hidden mode"         nocase ascii wide
        $s6 = "invisible"           nocase ascii wide
    condition:
        ($s1 or $s3) and ($s5 or $s6)
}

rule PUP_Coinminer_Binary
{
    meta:
        description = "Standalone cryptocurrency mining binary"
        severity    = "medium"
    strings:
        $xmr1 = "xmrig"            nocase ascii wide
        $xmr2 = "--cpu-priority"   ascii
        $xmr3 = "--donate-level"   ascii
        $pool = "pool.minexmr.com" ascii
        $pool2= "supportxmr.com"   ascii
        $pool3= "nanopool.org"     ascii
        $algo = "--algo=rx/0"      ascii
    condition:
        $xmr1 or ($xmr2 and $xmr3) or any of ($pool, $pool2, $pool3)
}

rule PUP_Dubious_Download_Manager
{
    meta:
        description = "Download manager that bundles unwanted software"
        severity    = "low"
    strings:
        $s1 = "download manager"    nocase ascii wide
        $s2 = "sponsored offer"     nocase ascii wide
        $s3 = "recommended software" nocase ascii wide
        $s4 = "install additional"  nocase ascii wide
        $s5 = "partner offer"       nocase ascii wide
    condition:
        2 of them
}
