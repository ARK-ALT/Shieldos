/*
 * ShieldOS YARA Rules — Trojans & RATs
 * Covers: banking trojans, RATs, loaders, stealers, backdoors.
 */

rule Trojan_Emotet_Loader
{
    meta:
        description = "Emotet banking trojan / loader artifacts"
        severity    = "critical"
        family      = "Emotet"
    strings:
        $s1  = "emotet"             nocase ascii
        $s2  = "heodo"              nocase ascii
        $reg = "HKCU\\Software\\"  ascii wide
        $psh = "powershell"         nocase ascii wide
        $iex = "IEX("              nocase ascii wide
        $enc = "-EncodedCommand"    nocase ascii wide
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $s1 or $s2 or
        ($reg and $psh and ($iex or $enc) and $b64)
}

rule Trojan_TrickBot
{
    meta:
        description = "TrickBot trojan artifacts"
        severity    = "critical"
        family      = "TrickBot"
    strings:
        $s1  = "trickbot"         nocase ascii
        $cfg = "mcconf.ini"       nocase ascii
        $mod = "systeminfo32"     nocase ascii wide
        $inj = "injectDll"        nocase ascii
        $grp = "group_tag"        nocase ascii
        $ver = "gtag"             ascii
    condition:
        $s1 or ($cfg and $ver) or ($inj and $grp)
}

rule RAT_AsyncRAT
{
    meta:
        description = "AsyncRAT remote access trojan"
        severity    = "critical"
        family      = "AsyncRAT"
    strings:
        $s1  = "AsyncRAT"         nocase ascii wide
        $s2  = "ServerCertificate" ascii wide
        $s3  = "Pastebin"         nocase ascii
        $cfg = "Ports"            ascii
        $hb  = "Heartbeat"        ascii wide
        $anti= "AntiAnalysis"     ascii wide
    condition:
        $s1 or ($s2 and $hb) or ($cfg and $anti)
}

rule RAT_QuasarRAT
{
    meta:
        description = "Quasar remote access trojan"
        severity    = "critical"
        family      = "QuasarRAT"
    strings:
        $s1  = "Quasar.Server"    ascii
        $s2  = "Quasar.Client"    ascii
        $s3  = "QuasarRAT"        nocase ascii
        $key = "HKCU\\Software\\Quasar" ascii wide
        $dll = "ClientPlugin"     ascii
    condition:
        any of them
}

rule RAT_NjRAT
{
    meta:
        description = "njRAT / Bladabindi remote access trojan"
        severity    = "critical"
        family      = "njRAT"
    strings:
        $s1 = "njRAT"           nocase ascii wide
        $s2 = "Bladabindi"      nocase ascii
        $s3 = "HoudRat"         nocase ascii
        $kl = "kl.txt"          ascii
        $mu = "[ENTER]"         ascii wide   // keylogger delimiter
    condition:
        any of ($s*) or ($kl and $mu)
}

rule Trojan_AgentTesla_Stealer
{
    meta:
        description = "Agent Tesla credential stealer"
        severity    = "critical"
        family      = "AgentTesla"
    strings:
        $s1   = "AgentTesla"       nocase ascii
        $smtp = "SmtpClient"       nocase ascii wide
        $pw   = "GetSavedPasswords" nocase ascii wide
        $ftp  = "FtpWebRequest"    nocase ascii wide
        $clip = "GetText()"        nocase ascii wide
        $scr  = "GetDesktopImage"  nocase ascii wide
    condition:
        $s1 or ($smtp and $pw) or ($ftp and $pw)
}

rule Trojan_FormBook_Stealer
{
    meta:
        description = "FormBook form grabber / stealer"
        severity    = "critical"
        family      = "FormBook"
    strings:
        $s1  = "formbook"         nocase ascii
        $api = "NtQueryInformationProcess" ascii wide
        $inj = "SetWindowsHookEx" nocase ascii wide
        $frm = "WM_COPYDATA"     ascii wide
    condition:
        $s1 or ($api and $inj and $frm)
}

rule Backdoor_Generic_Reverse_Shell
{
    meta:
        description = "Generic reverse shell backdoor"
        severity    = "critical"
    strings:
        $py1 = "import socket"                ascii
        $py2 = "socket.AF_INET"               ascii
        $py3 = "socket.SOCK_STREAM"           ascii
        $py4 = "subprocess.Popen"             ascii
        $py5 = "/bin/sh"                      ascii
        $ps1 = "$client = New-Object System.Net.Sockets.TCPClient" ascii wide
        $ps2 = "GetStream()"                  ascii wide
        $ps3 = "[System.Text.Encoding]::ASCII" ascii wide
    condition:
        ($py1 and $py2 and $py4 and $py5) or
        ($ps1 and $ps2 and $ps3)
}

rule Trojan_Generic_Persistence_Registry
{
    meta:
        description = "Trojan establishing registry persistence"
        severity    = "high"
    strings:
        $reg1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg2 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $set  = "RegSetValueEx"   nocase ascii wide
        $set2 = "Set-ItemProperty" nocase ascii wide
        $run  = "-WindowStyle Hidden" nocase ascii wide
    condition:
        (any of ($reg*)) and (any of ($set, $set2)) and $run
}

rule Trojan_Loader_Hollow_Process
{
    meta:
        description = "Process hollowing technique (loader/injector)"
        severity    = "critical"
    strings:
        $cp   = "CreateProcess"          nocase ascii wide
        $unmap= "NtUnmapViewOfSection"   ascii wide
        $vae  = "VirtualAllocEx"         nocase ascii wide
        $wpm  = "WriteProcessMemory"     nocase ascii wide
        $rt   = "ResumeThread"           nocase ascii wide
        $ctx  = "SetThreadContext"       nocase ascii wide
    condition:
        $cp and $unmap and $vae and $wpm and ($rt or $ctx)
}

rule Trojan_Reflective_DLL_Injection
{
    meta:
        description = "Reflective DLL injection pattern"
        severity    = "critical"
    strings:
        $rdll = "ReflectiveDllInjection" nocase ascii
        $ref  = "ReflectiveLoader"       nocase ascii
        $hash = { 04 C7 C7 C2 }          // RDI hash constant
    condition:
        any of ($rdll, $ref) or $hash
}
