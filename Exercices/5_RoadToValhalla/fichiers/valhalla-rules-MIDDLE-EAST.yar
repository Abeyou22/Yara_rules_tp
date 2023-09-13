/*
    VALHALLA YARA RULE SET
    Retrieved: 2023-09-13 11:32
    Generated for User: demo
    Number of Rules: 55
    
    This is the VALHALLA demo rule set. The content represents the 'signature-base' repository in a streamlined format but lacks the rules provided by 3rd parties. All rules are licensed under CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/.
*/

import "pe"

rule MAL_ME_RawDisk_Agent_Jan20_2_RID30A9 : DEMO EXE FILE MAL MIDDLE_EAST {
   meta:
      description = "Detects suspicious malware using ElRawDisk"
      author = "Florian Roth"
      reference = "https://twitter.com/jfslowik/status/1212501454549741568?s=09"
      date = "2020-01-02 12:49:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "44100c73c6e2529c591a10cd3668691d92dc0241152ec82a72c6e63da299d3a2"
      tags = "DEMO, EXE, FILE, MAL, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "\\Release\\Dustman.pdb" ascii
      $x2 = "/c agent.exe A" fullword ascii
      $s1 = "C:\\windows\\system32\\cmd.exe" fullword ascii
      $s2 = "The Magic Word!" fullword ascii
      $s3 = "Software\\Oracle\\VirtualBox" fullword wide
      $s4 = "\\assistant.sys" wide
      $s5 = "Down With Bin Salman" fullword wide
      $sc1 = { 00 5C 00 5C 00 2E 00 5C 00 25 00 73 } 
      $op1 = { 49 81 c6 ff ff ff 7f 4c 89 b4 24 98 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize <= 3000KB and ( 1 of ( $x* ) or 3 of them )
}

rule MAL_ME_RawDisk_Agent_Jan20_1_RID30A8 : DEMO EXE FILE MAL MIDDLE_EAST {
   meta:
      description = "Detects suspicious malware using ElRawDisk"
      author = "Florian Roth"
      reference = "Saudi National Cybersecurity Authority - Destructive Attack DUSTMAN"
      date = "2020-01-02 12:49:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "44100c73c6e2529c591a10cd3668691d92dc0241152ec82a72c6e63da299d3a2"
      tags = "DEMO, EXE, FILE, MAL, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "\\drv\\agent.plain.pdb" ascii
      $x2 = " ************** Down With Saudi Kingdom, Down With Bin Salman ************** " fullword ascii
      $s1 = ".?AVERDError@@" fullword ascii
      $s2 = "b4b615c28ccd059cf8ed1abf1c71fe03c0354522990af63adf3c911e2287a4b906d47d" fullword wide
      $s3 = "\\\\?\\ElRawDisk" fullword wide
      $s4 = "\\??\\c:" wide
      $op1 = { e9 3d ff ff ff 33 c0 48 89 05 0d ff 00 00 48 8b } 
      $op2 = { 0f b6 0c 01 88 48 34 48 8b 8d a8 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize <= 2000KB and ( 1 of ( $x* ) or 4 of them )
}

rule APT_APT34_PS_Malware_Apr19_1_RID3047 : APT DEMO G0049 G0057 MIDDLE_EAST SCRIPT T1059_001 {
   meta:
      description = "Detects APT34 PowerShell malware"
      author = "Florian Roth"
      reference = "https://twitter.com/0xffff0800/status/1118406371165126656"
      date = "2019-04-17 12:33:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b1d621091740e62c84fc8c62bcdad07873c8b61b83faba36097ef150fd6ec768"
      tags = "APT, DEMO, G0049, G0057, MIDDLE_EAST, SCRIPT, T1059_001"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "= get-wmiobject Win32_ComputerSystemProduct  | Select-Object -ExpandProperty UUID" ascii
      $x2 = "Write-Host \"excepton occured!\"" ascii
      $s1 = "Start-Sleep -s 1;" fullword ascii
      $s2 = "Start-Sleep -m 100;" fullword ascii
   condition: 
      1 of ( $x* ) or 2 of them
}

rule APT_APT34_PS_Malware_Apr19_2_RID3048 : APT DEMO G0049 G0057 MIDDLE_EAST SCRIPT T1059_001 {
   meta:
      description = "Detects APT34 PowerShell malware"
      author = "Florian Roth"
      reference = "https://twitter.com/0xffff0800/status/1118406371165126656"
      date = "2019-04-17 12:33:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2943e69e6c34232dee3236ced38d41d378784a317eeaf6b90482014210fcd459"
      tags = "APT, DEMO, G0049, G0057, MIDDLE_EAST, SCRIPT, T1059_001"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "= \"http://\" + [System.Net.Dns]::GetHostAddresses(\"" ascii
      $x2 = "$t = get-wmiobject Win32_ComputerSystemProduct  | Select-Object -ExpandProperty UUID" fullword ascii
      $x3 = "| Where { $_ -notmatch '^\\s+$' }" ascii
      $s1 = "= new-object System.Net.WebProxy($u, $true);" fullword ascii
      $s2 = " -eq \"dom\"){$" ascii
      $s3 = " -eq \"srv\"){$" ascii
      $s4 = "+\"<>\" | Set-Content" ascii
   condition: 
      1 of ( $x* ) and 3 of them
}

rule APT_APT34_PS_Malware_Apr19_3_RID3049 : APT DEMO G0049 G0057 MIDDLE_EAST SCRIPT T1053_005 T1059_001 {
   meta:
      description = "Detects APT34 PowerShell malware"
      author = "Florian Roth"
      reference = "https://twitter.com/0xffff0800/status/1118406371165126656"
      date = "2019-04-17 12:33:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      hash1 = "27e03b98ae0f6f2650f378e9292384f1350f95ee4f3ac009e0113a8d9e2e14ed"
      tags = "APT, DEMO, G0049, G0057, MIDDLE_EAST, SCRIPT, T1053_005, T1059_001"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "Powershell.exe -exec bypass -file ${global:$address1}" 
      $x2 = "schtasks /create /F /ru SYSTEM /sc minute /mo 10 /tn" 
      $x3 = "\"\\UpdateTasks\\UpdateTaskHosts\"" 
      $x4 = "wscript /b \\`\"${global:$address1" ascii
      $x5 = "::FromBase64String([string]${global:$http_ag}))" ascii
      $x6 = ".run command1, 0, false\" | Out-File " ascii
      $x7 = "\\UpdateTask.vbs" ascii
      $x8 = "hUpdater.ps1" fullword ascii
   condition: 
      1 of them
}

rule APT_DarkHydrus_Jul18_1_RID2ED9 : APT DEMO EXE FILE G0079 MIDDLE_EAST {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28 11:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "99541ab28fc3328e25723607df4b0d9ea0a1af31b58e2da07eff9f15c4e6565c"
      tags = "APT, DEMO, EXE, FILE, G0079, MIDDLE_EAST"
      required_modules = "pe"
      minimum_yara = "3.2.0"
      
   strings:
      $x1 = "Z:\\devcenter\\aggressor\\" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "d3666d1cde4790b22b44ec35976687fb" or 1 of them )
}

rule APT_DarkHydrus_Jul18_2_RID2EDA : APT DEMO EXE FILE G0079 MIDDLE_EAST {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28 11:32:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b2571e3b4afbce56da8faa726b726eb465f2e5e5ed74cf3b172b5dd80460ad81"
      tags = "APT, DEMO, EXE, FILE, G0079, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $s4 = "windir" fullword ascii
      $s6 = "temp.dll" fullword ascii
      $s7 = "libgcj-12.dll" fullword ascii
      $s8 = "%s\\System32\\%s" fullword ascii
      $s9 = "StartW" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 40KB and all of them
}

rule APT_DarkHydrus_Jul18_3_RID2EDB : APT DEMO EXE FILE G0079 MIDDLE_EAST {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28 11:32:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c8b3d4b6acce6b6655e17255ef7a214651b7fc4e43f9964df24556343393a1a3"
      tags = "APT, DEMO, EXE, FILE, G0079, MIDDLE_EAST"
      required_modules = "pe"
      minimum_yara = "3.2.0"
      
   strings:
      $s2 = "Ws2_32.dll" fullword ascii
      $s3 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and ( pe.imphash ( ) == "478eacfbe2b201dabe63be53f34148a5" or all of them )
}

rule HKTL_Unlicensed_CobaltStrike_EICAR_Jul18_5_RID361D : APT COBALTSTRIKE DEMO EXE FILE G0079 HKTL MIDDLE_EAST S0154 T1550_002 {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28 16:42:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2020-10-13"
      hash1 = "cec36e8ed65ac6f250c05b4a17c09f58bb80c19b73169aaf40fa15c8d3a9a6a1"
      tags = "APT, COBALTSTRIKE, DEMO, EXE, FILE, G0079, HKTL, MIDDLE_EAST, S0154, T1550_002"
      required_modules = "pe"
      minimum_yara = "3.2.0"
      
   strings:
      $x1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 
      $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii
      $s2 = "libgcj-12.dll" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 900KB and ( pe.imphash ( ) == "829da329ce140d873b4a8bde2cbfaa7e" or all of ( $s* ) or $x1 )
}

rule APT_ME_BigBang_Gen_Jul18_1_RID2FCC : APT DEMO EXE FILE GEN MIDDLE_EAST {
   meta:
      description = "Detects malware from Big Bang campaign against Palestinian authorities"
      author = "Florian Roth"
      reference = "https://research.checkpoint.com/apt-attack-middle-east-big-bang/"
      date = "2018-07-09 12:12:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4db68522600f2d8aabd255e2da999a9d9c9f1f18491cfce9dadf2296269a172b"
      hash2 = "ac6462e9e26362f711783b9874d46fefce198c4c3ca947a5d4df7842a6c51224"
      hash3 = "e1f52ea30d25289f7a4a5c9d15be97c8a4dfe10eb68ac9d031edcc7275c23dbc"
      tags = "APT, DEMO, EXE, FILE, GEN, MIDDLE_EAST"
      required_modules = "pe"
      minimum_yara = "3.2.0"
      
   strings:
      $x2 = "%@W@%S@c@ri%@p@%t.S@%he@%l%@l" ascii
      $x3 = "S%@h%@e%l%@l." ascii
      $x4 = "(\"S@%t@%a%@rt%@up\")" ascii
      $x5 = "aW5zdGFsbCBwcm9nOiBwcm9nIHdpbGwgZGVsZXRlIG9sZCB0bXAgZmlsZQ==" fullword ascii
      $x6 = "aW5zdGFsbCBwcm9nOiBUaGVyZSBpcyBubyBvbGQgZmlsZSBpbiB0ZW1wLg==" fullword ascii
      $x7 = "VXBkYXRlIHByb2c6IFRoZXJlIGlzIG5vIG9sZCBmaWxlIGluIHRlbXAu" fullword ascii
      $x8 = "aW5zdGFsbCBwcm9nOiBDcmVhdGUgVGFzayBhZnRlciA1IG1pbiB0byBydW4gRmlsZSBmcm9tIHRtcA==" fullword ascii
      $x9 = "UnVuIEZpbGU6IE15IHByb2cgaXMgRXhpdC4=" fullword ascii
      $x10 = "li%@%@nk.W%@%@indo@%%@%@%wS%@%@tyle = 3" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and ( 1 of them or pe.imphash ( ) == "0f09ea2a68d04f331df9a5d0f8641332" )
}

rule APT_ME_BigBang_Mal_Jul18_1_RID2FCC : APT DEMO EXE FILE MAL MIDDLE_EAST {
   meta:
      description = "Detects malware from Big Bang report"
      author = "Florian Roth"
      reference = "https://research.checkpoint.com/apt-attack-middle-east-big-bang/"
      date = "2018-07-09 12:12:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ac6462e9e26362f711783b9874d46fefce198c4c3ca947a5d4df7842a6c51224"
      hash2 = "e1f52ea30d25289f7a4a5c9d15be97c8a4dfe10eb68ac9d031edcc7275c23dbc"
      tags = "APT, DEMO, EXE, FILE, MAL, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "%Y%m%d-%I-%M-%S" fullword ascii
      $s2 = "/api/serv/requests/%s/runfile/delete" fullword ascii
      $s3 = "\\part.txt" ascii
      $s4 = "\\ALL.txt" ascii
      $s5 = "\\sat.txt" ascii
      $s6 = "runfile.proccess_name" fullword ascii
      $s7 = "%s%s%p%s%zd%s%d%s%s%s%s%s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 4 of them
}

rule MAL_AirdViper_Sample_Apr18_1_RID310C : APT DEMO EXE FILE MAL MIDDLE_EAST {
   meta:
      description = "Detects Arid Viper malware sample"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-04 13:05:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f453f1d5088bd17c60e812289b4bb0a734b7ad2ba5a536f5fd6d6ac3b8f3397"
      tags = "APT, DEMO, EXE, FILE, MAL, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s\"" fullword ascii
      $x2 = "daenerys=%s&" ascii
      $x3 = "betriebssystem=%s&anwendung=%s&AV=%s" ascii
      $s1 = "Taskkill /IM  %s /F &  %s" fullword ascii
      $s2 = "/api/primewire/%s/requests/macKenzie/delete" fullword ascii
      $s3 = "\\TaskWindows.exe" ascii
      $s4 = "MicrosoftOneDrives.exe" fullword ascii
      $s5 = "\\SeanSansom.txt" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 6000KB and ( 1 of ( $x* ) or 4 of them )
}

rule Chafer_Mimikatz_Custom_RID2FD9 : APT DEMO EXE FILE G0087 MIDDLE_EAST S0002 T1003 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Detects Custom Mimikatz Version"
      author = "Florian Roth, Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22 12:14:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9709afeb76532566ee3029ecffc76df970a60813bcac863080cc952ad512b023"
      tags = "APT, DEMO, EXE, FILE, G0087, MIDDLE_EAST, S0002, T1003, T1134_005, T1550_002, T1550_003"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "C:\\Users\\win7p\\Documents\\mi-back\\" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule Chafer_Exploit_Copyright_2017_RID31DF : APT DEMO EXE EXPLOIT FILE G0049 G0087 MIDDLE_EAST {
   meta:
      description = "Detects Oilrig Internet Server Extension with Copyright (C) 2017 Exploit"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22 13:41:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cdac69caad8891c5e1b8eabe598c869674dee30af448ce4e801a90eb79973c66"
      tags = "APT, DEMO, EXE, EXPLOIT, FILE, G0049, G0087, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "test3 Internet Server Extension" fullword wide
      $x2 = "Copyright (C) 2017 Exploit" fullword wide
      $a1 = "popen() failed!" fullword ascii
      $a2 = "cmd2cmd=" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and ( 1 of ( $x* ) or all of ( $a* ) )
}

rule Oilrig_Myrtille_RID2D28 : APT DEMO EXE FILE G0049 MIDDLE_EAST T1021_001 {
   meta:
      description = "Detects Oilrig Myrtille RDP Browser"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22 10:19:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "67945f2e65a4a53e2339bd361652c6663fe25060888f18e681418e313d1292ca"
      tags = "APT, DEMO, EXE, FILE, G0049, MIDDLE_EAST, T1021_001"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "\\obj\\Release\\Myrtille.Services.pdb" ascii
      $x2 = "Failed to notify rdp client process exit (MyrtilleAppPool down?), remote session {0} ({1})" fullword wide
      $x3 = "Started rdp client process, remote session {0}" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 50KB and 1 of them
}

rule Chafer_Packed_Mimikatz_RID2FA6 : APT DEMO EXE FILE G0049 G0087 MIDDLE_EAST S0002 T1003 T1027_002 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Detects Oilrig Packed Mimikatz also detected as Chafer_WSC_x64 by FR"
      author = "Florian Roth, Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22 12:06:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5f2c3b5a08bda50cca6385ba7d84875973843885efebaff6a482a38b3cb23a7c"
      tags = "APT, DEMO, EXE, FILE, G0049, G0087, MIDDLE_EAST, S0002, T1003, T1027_002, T1134_005, T1550_002, T1550_003"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "Windows Security Credentials" fullword wide
      $s2 = "Minisoft" fullword wide
      $x1 = "Copyright (c) 2014 - 2015 Minisoft" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and ( all of ( $s* ) or $x1 )
}

rule Oilrig_PS_CnC_RID2BCC : APT DEMO G0049 MIDDLE_EAST SCRIPT T1059_001 {
   meta:
      description = "Powershell CnC using DNS queries"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22 09:21:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9198c29a26f9c55317b4a7a722bf084036e93a41ba4466cbb61ea23d21289cfa"
      tags = "APT, DEMO, G0049, MIDDLE_EAST, SCRIPT, T1059_001"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "(-join $base32filedata[$uploadedCompleteSize..$($uploadedCompleteSize" fullword ascii
      $s2 = "$hostname = \"D\" + $fileID + (-join ((65..90) + (48..57) + (97..122)|" ascii
   condition: 
      filesize < 40KB and 1 of them
}

rule ME_Campaign_Malware_1_RID2EDA : APT DEMO EXE FILE MIDDLE_EAST {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07 11:32:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1176642841762b3bc1f401a5987dc55ae4b007367e98740188468642ffbd474e"
      tags = "APT, DEMO, EXE, FILE, MIDDLE_EAST"
      required_modules = "pe"
      minimum_yara = "3.2.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5000KB and ( pe.imphash ( ) == "618f76eaf4bd95c690d43e84d617efe9" )
}

rule ME_Campaign_Malware_2_RID2EDB : APT DEMO EXE FILE MIDDLE_EAST {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07 11:32:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "76a9b603f1f901020f65358f1cbf94c1a427d9019f004a99aa8bff1dea01a881"
      tags = "APT, DEMO, EXE, FILE, MIDDLE_EAST"
      required_modules = "pe"
      minimum_yara = "3.2.0"
      
   strings:
      $s1 = "QuickAssist.exe" fullword wide
      $s2 = "<description>Microsoft Modern Sharing Solution</description>" fullword ascii
      $s3 = "GBEWCWA" fullword ascii
      $s4 = "name=\"QuickAssist\" " fullword ascii
      $s5 = "Cimzal" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "b06055e6cc2a804111ab6964df1ca4ae" or 4 of them )
}

rule ME_Campaign_Malware_3_RID2EDC : APT DEMO FILE MIDDLE_EAST {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07 11:32:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "15f5aaa71bfa3d62fd558a3e88dd5ba26f7638bf2ac653b8d6b8d54dc7e5926b"
      tags = "APT, DEMO, FILE, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "objWShell.Run \"powershell.exe -ExecutionPolicy Bypass -File \"\"%appdata%\"\"\\sys.ps1\", 0 " fullword ascii
      $x2 = "objFile.WriteLine \"New-Item -Path \"\"$ENV:APPDATA\\Microsoft\\Templates\"\" -ItemType Directory -Force }\" " fullword ascii
      $x3 = "objFile.WriteLine \"$path = \"\"$ENV:APPDATA\\Microsoft\\Templates\\Report.doc\"\"\" " fullword ascii
      $s4 = "File=appData & \"\\sys.ps1\"" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x6553 and filesize < 400KB and 1 of them
}

rule ME_Campaign_Malware_4_RID2EDD : APT DEMO EXE FILE MIDDLE_EAST {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07 11:32:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c5bfb5118a999d21e9f445ad6ccb08eb71bc7bd4de9e88a41be9cf732156c525"
      tags = "APT, DEMO, EXE, FILE, MIDDLE_EAST"
      required_modules = "pe"
      minimum_yara = "3.2.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and pe.imphash ( ) == "fb7da233a35ac523d6059fff543627ab"
}

rule ME_Campaign_Malware_5_RID2EDE : APT DEMO EXE MIDDLE_EAST T1047 {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07 11:32:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-08-18"
      hash1 = "d49e9fdfdce1e93615c406ae13ac5f6f68fb7e321ed4f275f328ac8146dd0fc1"
      hash2 = "e66af059f37bdd35056d1bb6a1ba3695fc5ce333dc96b5a7d7cc9167e32571c5"
      tags = "APT, DEMO, EXE, MIDDLE_EAST, T1047"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "D:\\me\\do\\do\\obj\\" ascii
      $s2 = "Select * from Win32_ComputerSystem" fullword wide
      $s3 = "Get_Antivirus" fullword ascii
      $s4 = "{{\"id\":\"{0}\",\"user\":\"{1}\",\"path\":\"{2}\"}}" fullword wide
      $s5 = "update software online" fullword wide
      $s6 = "time.nist.gov" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 60KB and 5 of them or all of them
}

rule OilRig_RGDoor_Gen1_RID2D8D : APT DEMO EXE FILE G0049 MIDDLE_EAST {
   meta:
      description = "Detects RGDoor backdoor used by OilRig group"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/"
      date = "2018-01-27 10:36:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a9c92b29ee05c1522715c7a2f9c543740b60e36373cb47b5620b1f3d8ad96bfa"
      tags = "APT, DEMO, EXE, FILE, G0049, MIDDLE_EAST"
      required_modules = "pe"
      minimum_yara = "3.2.0"
      
   strings:
      $c1 = { 00 63 6D 64 24 00 00 00 00 72 00 00 00 00 00 00 00 75 70 6C 6F
              61 64 24 } 
      $c2 = { 63 61 6E 27 74 20 6F 70 65 6E 20 66 69 6C 65 3A 20 00 00 00 00
              00 00 00 64 6F 77 6E 6C 6F 61 64 24 } 
      $s1 = "MyNativeModule.dll" fullword ascii
      $s2 = "RGSESSIONID=" fullword ascii
      $s3 = "download$" fullword ascii
      $s4 = ".?AVCHelloWorld@@" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "47cb127aad6c7c9954058e61a2a6429a" or 1 of ( $c* ) or 2 of them )
}

rule APT34_Malware_HTA_RID2CC1 : DEMO G0049 G0057 MAL MIDDLE_EAST {
   meta:
      description = "Detects APT 34 malware"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
      date = "2017-12-07 10:02:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f6fa94cc8efea0dbd7d4d4ca4cf85ac6da97ee5cf0c59d16a6aafccd2b9d8b9a"
      tags = "DEMO, G0049, G0057, MAL, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "WshShell.run \"cmd.exe /C C:\\ProgramData\\" ascii
      $x2 = ".bat&ping 127.0.0.1 -n 6 > nul&wscript  /b" ascii
      $x3 = "cmd.exe /C certutil -f  -decode C:\\ProgramData\\" ascii
      $x4 = "a.WriteLine(\"set Shell0 = CreateObject(" ascii
      $x5 = "& vbCrLf & \"Shell0.run" ascii
      $s1 = "<title>Blog.tkacprow.pl: HTA Hello World!</title>" fullword ascii
      $s2 = "<body onload=\"test()\">" fullword ascii
   condition: 
      filesize < 60KB and ( 1 of ( $x* ) or all of ( $s* ) )
}

rule APT34_Malware_Exeruner_RID2F32 : DEMO EXE FILE G0049 G0057 MAL MIDDLE_EAST T1053_005 {
   meta:
      description = "Detects APT 34 malware"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
      date = "2017-12-07 11:46:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c75c85acf0e0092d688a605778425ba4cb2a57878925eee3dc0f4dd8d636a27a"
      tags = "DEMO, EXE, FILE, G0049, G0057, MAL, MIDDLE_EAST, T1053_005"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "\\obj\\Debug\\exeruner.pdb" ascii
      $x2 = "\"wscript.shell`\")`nShell0.run" wide
      $x3 = "powershell.exe -exec bypass -enc \" + ${global:$http_ag} +" wide
      $x4 = "/c powershell -exec bypass -window hidden -nologo -command " fullword wide
      $x5 = "\\UpdateTasks\\JavaUpdatesTasksHosts\\" wide
      $x6 = "schtasks /create /F /ru SYSTEM /sc minute /mo 1 /tn" wide
      $x7 = "UpdateChecker.ps1 & ping 127.0.0.1" wide
      $s8 = "exeruner.exe" fullword wide
      $s9 = "${global:$address1} = $env:ProgramData + \"\\Windows\\Microsoft\\java\";" fullword wide
      $s10 = "C:\\ProgramData\\Windows\\Microsoft\\java" fullword wide
      $s11 = "function runByVBS" fullword wide
      $s12 = "$84e31856-683b-41c0-81dd-a02d8b795026" fullword ascii
      $s13 = "${global:$dns_ag} = \"aQBmACAAKAAoAEcAZQB0AC0AVwBtAGk" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them
}

rule Greenbug_Malware_Nov17_1_RID2FF2 : DEMO EXE FILE MAL MIDDLE_EAST {
   meta:
      description = "Detects Greenbug Malware"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/greenbug/"
      date = "2017-11-26 12:18:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6e55e161dc9ace3076640a36ef4a8819bb85c6d5e88d8e852088478f79cf3b7c"
      hash2 = "a9f1375da973b229eb649dc3c07484ae7513032b79665efe78c0e55a6e716821"
      tags = "DEMO, EXE, FILE, MAL, MIDDLE_EAST"
      required_modules = "pe"
      minimum_yara = "3.2.0"
      
   strings:
      $x1 = "AgentV2.exe  -c  SampleDomain.com" fullword ascii
      $x2 = ".ntpupdateserver.com" fullword ascii
      $x3 = "Content-Disposition: form-data; name=\"file\"; filename=\"a.a\"" fullword ascii
      $x4 = "a67d0db885a3432576548a2a03707334" fullword ascii
      $x5 = "a67d0db8a2a173347654432503702aa3" fullword ascii
      $x6 = "!!! can not create output file !!!" fullword ascii
      $s1 = "\\runlog*" ascii
      $s2 = "can not specify username!!" fullword ascii
      $s3 = "Agent can not be configured" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and ( pe.imphash ( ) == "58ba44f7ff5436a603fec3df97d815ea" or pe.imphash ( ) == "538805ecd776b9a42e71aebf94fde1b1" or 1 of ( $x* ) or 3 of them )
}

rule OilRig_Malware_Nov17_13_RID2F3C : DEMO EXE FILE G0049 MAL MIDDLE_EAST {
   meta:
      description = "Detects OilRig DNSCat malware"
      author = "Florian Roth"
      reference = "https://twitter.com/ClearskySec/status/933280188733018113"
      date = "2017-11-22 11:48:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4f1e2df85c538875a7da877719555e21c33a558ac121eb715cf4e779d77ab445"
      tags = "DEMO, EXE, FILE, G0049, MAL, MIDDLE_EAST"
      required_modules = "pe"
      minimum_yara = "3.2.0"
      
   strings:
      $x1 = "\\Release\\dnscat2.pdb" ascii
      $x2 = "cscript.exe //T:20 //Nologo " fullword ascii
      $a1 = "taskkill /F /IM cscript.exe" fullword ascii
      $a2 = "cmd.exe /c " fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and ( pe.imphash ( ) == "0160250adfc97f9d4a12dd067323ec61" or 1 of ( $x* ) or all of ( $a* ) )
}

rule OilRig_Strings_Oct17_RID2E8D : APT DEMO G0049 MIDDLE_EAST {
   meta:
      description = "Detects strings from OilRig malware and malicious scripts"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/"
      date = "2017-10-18 11:19:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      tags = "APT, DEMO, G0049, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "%localappdata%\\srvHealth.exe" fullword wide ascii
      $x2 = "%localappdata%\\srvBS.txt" fullword wide ascii
      $x3 = "Agent Injector\\PolicyConverter\\Inner\\obj\\Release\\Inner.pdb" ascii
      $x4 = "Agent Injector\\PolicyConverter\\Joiner\\obj\\Release\\Joiner.pdb" ascii
      $s3 = ".LoadDll(\"Run\", arg, \"C:\\\\Windows\\\\" ascii
   condition: 
      filesize < 800KB and 1 of them
}

rule OilRig_ISMAgent_Campaign_Samples1_RID3372 : APT DEMO FILE G0049 MIDDLE_EAST {
   meta:
      description = "Detects OilRig malware from Unit 42 report in October 2017"
      author = "Florian Roth"
      reference = "https://goo.gl/JQVfFP"
      date = "2017-10-18 14:48:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "119c64a8b35bd626b3ea5f630d533b2e0e7852a4c59694125ff08f9965b5f9cc"
      hash2 = "0ccb2117c34e3045a4d2c0d193f1963c8c0e8566617ed0a561546c932d1a5c0c"
      tags = "APT, DEMO, FILE, G0049, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "###$$$TVqQAAMAAAAEAAAA" ascii
      $s2 = "C:\\Users\\J-Win-7-32-Vm\\Desktop\\error.jpg" fullword wide
      $s3 = "$DATA = [System.Convert]::FromBase64String([IO.File]::ReadAllText('%Base%'));[io.file]::WriteAllBytes(" ascii
      $s4 = " /c echo powershell > " fullword wide ascii
      $s5 = "\\Libraries\\servicereset.exe" wide
      $s6 = "%DestFolder%" fullword wide ascii
   condition: 
      uint16 ( 0 ) == 0xcfd0 and filesize < 3000KB and 2 of them
}

rule OilRig_ISMAgent_Campaign_Samples2_RID3373 : APT DEMO EXE FILE G0049 MIDDLE_EAST T1218_009 {
   meta:
      description = "Detects OilRig malware from Unit 42 report in October 2017"
      author = "Florian Roth"
      reference = "https://goo.gl/JQVfFP"
      date = "2017-10-18 14:48:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fcad263d0fe2b418db05f47d4036f0b42aaf201c9b91281dfdcb3201b298e4f4"
      hash2 = "33c187cfd9e3b68c3089c27ac64a519ccc951ccb3c74d75179c520f54f11f647"
      tags = "APT, DEMO, EXE, FILE, G0049, MIDDLE_EAST, T1218_009"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "PolicyConverter.exe" fullword wide
      $x2 = "SrvHealth.exe" fullword wide
      $x3 = "srvBS.txt" fullword wide
      $s1 = "{a3538ba3-5cf7-43f0-bc0e-9b53a98e1643}, PublicKeyToken=3e56350693f7355e" fullword wide
      $s2 = "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\RegAsm.exe" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and ( 2 of ( $x* ) or 3 of them )
}

rule StoneDrill_BAT_1_RID2CD7 : APT DEMO FILE MIDDLE_EAST SCRIPT {
   meta:
      description = "Rule to detect Batch file from StoneDrill report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07 10:06:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, MIDDLE_EAST, SCRIPT"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "set u100=" ascii
      $s2 = "set u200=service" ascii fullword
      $s3 = "set u800=%~dp0" ascii fullword
      $s4 = "\"%systemroot%\\system32\\%u100%\"" ascii
      $s5 = "%\" start /b %systemroot%\\system32\\%" ascii
   condition: 
      uint32 ( 0 ) == 0x68636540 and 2 of them and filesize < 500
}

rule StoneDrill_Service_Install_RID3177 : APT DEMO MIDDLE_EAST SCRIPT T1569_002 {
   meta:
      description = "Rule to detect Batch file from StoneDrill report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07 13:23:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, MIDDLE_EAST, SCRIPT, T1569_002"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "127.0.0.1 >nul && sc config" ascii
      $s2 = "LocalService\" && ping -n" ascii fullword
      $s3 = "127.0.0.1 >nul && sc start" ascii fullword
      $s4 = "sc config NtsSrv binpath= \"C:\\WINDOWS\\system32\ntssrvr64.exe" ascii
   condition: 
      2 of them and filesize < 500
}

rule StoneDrill_ntssrvr32_RID2EF7 : APT DEMO EXE FILE MIDDLE_EAST {
   meta:
      description = "Detects malware from StoneDrill threat report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07 11:37:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-20"
      hash1 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"
      tags = "APT, DEMO, EXE, FILE, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "g\\system32\\" wide
      $s2 = "ztvttw" fullword wide
      $s3 = "lwizvm" fullword ascii
      $op1 = { 94 35 77 73 03 40 eb e9 } 
      $op2 = { 80 7c 41 01 00 74 0a 3d } 
      $op3 = { 74 0a 3d 00 94 35 77 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 4000KB and 3 of them )
}

rule StoneDrill_Malware_2_RID2ECA : APT DEMO EXE MIDDLE_EAST T1047 {
   meta:
      description = "Detects malware from StoneDrill threat report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07 11:29:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "69530d78c86031ce32583c6800f5ffc629acacb18aac4c8bb5b0e915fc4cc4db"
      tags = "APT, DEMO, EXE, MIDDLE_EAST, T1047"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "cmd /c WMIC Process Call Create \"C:\\Windows\\System32\\Wscript.exe //NOLOGO " fullword wide
      $s2 = "C:\\ProgramData\\InternetExplorer" fullword wide
      $s3 = "WshShell.CopyFile \"" fullword wide
      $s4 = "Abd891.tmp" fullword wide
      $s5 = "Set WshShell = Nothing" fullword wide
      $s6 = "AaCcdDeFfGhiKLlMmnNoOpPrRsSTtUuVvwWxyZz32" fullword ascii
      $s7 = "\\FileInfo.txt" wide
      $x1 = "C-PDI-C-Cpy-T.vbs" fullword wide
      $x2 = "C-Dlt-C-Org-T.vbs" fullword wide
      $x3 = "C-PDC-C-Cpy-T.vbs" fullword wide
      $x4 = "AC-PDC-C-Cpy-T.vbs" fullword wide
      $x5 = "C-Dlt-C-Trsh-T.tmp" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 700KB and ( 1 of ( $x* ) or 3 of ( $s* ) ) ) or 5 of them
}

rule StoneDrill_RID2B11 : APT DEMO EXE FILE MIDDLE_EAST {
   meta:
      description = "Detects malware from StoneDrill_RID2B11 threat report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07 08:50:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2bab3716a1f19879ca2e6d98c518debb107e0ed8e1534241f7769193807aac83"
      hash2 = "62aabce7a5741a9270cddac49cd1d715305c1d0505e620bbeaec6ff9b6fd0260"
      hash3 = "69530d78c86031ce32583c6800f5ffc629acacb18aac4c8bb5b0e915fc4cc4db"
      tags = "APT, DEMO, EXE, FILE, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "C-Dlt-C-Trsh-T.tmp" fullword wide
      $x2 = "C-Dlt-C-Org-T.vbs" fullword wide
      $s1 = "Hello dear" fullword ascii
      $s2 = "WRZRZRAR" fullword ascii
      $opa1 = { 66 89 45 d8 6a 64 ff } 
      $opa2 = { 8d 73 01 90 0f bf 51 fe } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and 1 of ( $x* ) or ( all of ( $op* ) and all of ( $s* ) )
}

rule StoneDrill_VBS_1_RID2CEB : APT DEMO MIDDLE_EAST SCRIPT {
   meta:
      description = "Detects malware from StoneDrill threat report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07 10:09:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0f4d608a87e36cb0dbf1b2d176ecfcde837070a2b2a049d532d3d4226e0c9587"
      tags = "APT, DEMO, MIDDLE_EAST, SCRIPT"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "wmic /NameSpace:\\\\root\\default Class StdRegProv Call SetStringValue hDefKey = \"&H80000001\" sSubKeyName = \"Software\\Micros" ascii
      $x2 = "ping 1.0.0.0 -n 1 -w 20000 > nul" fullword ascii
      $s1 = "WshShell.CopyFile \"%COMMON_APPDATA%\\Chrome\\" ascii
      $s2 = "WshShell.DeleteFile \"%temp%\\" ascii
      $s3 = "WScript.Sleep(10 * 1000)" fullword ascii
      $s4 = "Set WshShell = CreateObject(\"Scripting.FileSystemObject\") While WshShell.FileExists(\"" ascii
      $s5 = " , \"%COMMON_APPDATA%\\Chrome\\" ascii
   condition: 
      ( filesize < 1KB and 1 of ( $x* ) or 2 of ( $s* ) )
}

rule Greenbug_Malware_1_RID2DF8 : DEMO EXE FILE MAL MIDDLE_EAST {
   meta:
      description = "Detects Malware from Greenbug Incident"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25 10:54:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dab460a0b73e79299fbff2fa301420c1d97a36da7426acc0e903c70495db2b76"
      tags = "DEMO, EXE, FILE, MAL, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "vailablez" fullword ascii
      $s2 = "Sfouglr" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them )
}

rule Greenbug_Malware_2_RID2DF9 : DEMO EXE FILE MAL MIDDLE_EAST T1047 {
   meta:
      description = "Detects Backdoor from Greenbug Incident"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25 10:54:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6b28a43eda5b6f828a65574e3f08a6d00e0acf84cbb94aac5cec5cd448a4649d"
      hash2 = "21f5e60e9df6642dbbceca623ad59ad1778ea506b7932d75ea8db02230ce3685"
      hash3 = "319a001d09ee9d754e8789116bbb21a3c624c999dae9cf83fde90a3fbe67ee6c"
      tags = "DEMO, EXE, FILE, MAL, MIDDLE_EAST, T1047"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "|||Command executed successfully" fullword ascii
      $x2 = "\\Release\\Bot Fresh.pdb" ascii
      $x3 = "C:\\ddd\\a1.txt" fullword wide
      $x4 = "Bots\\Bot5\\x64\\Release" ascii
      $x5 = "Bot5\\Release\\Ism.pdb" ascii
      $x6 = "Bot\\Release\\Ism.pdb" ascii
      $x7 = "\\Bot Fresh\\Release\\Bot" ascii
      $s1 = "/Home/SaveFile?commandId=CmdResult=" fullword wide
      $s2 = "raB3G:Sun:Sunday:Mon:Monday:Tue:Tuesday:Wed:Wednesday:Thu:Thursday:Fri:Friday:Sat:Saturday" fullword ascii
      $s3 = "Set-Cookie:\\b*{.+?}\\n" fullword wide
      $s4 = "SELECT * FROM AntiVirusProduct" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and ( 1 of ( $x* ) or 2 of them ) ) or ( 3 of them )
}

rule Greenbug_Malware_3_RID2DFA : DEMO MAL MIDDLE_EAST {
   meta:
      description = "Detects Backdoor from Greenbug Incident"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25 10:54:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49"
      hash2 = "7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c"
      tags = "DEMO, MAL, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "F:\\Projects\\Bot\\Bot\\Release\\Ism.pdb" fullword ascii
      $x2 = "C:\\ddd\\wer2.txt" fullword wide
      $x3 = "\\Microsoft\\Windows\\tmp43hh11.txt" wide
   condition: 
      1 of them
}

rule Greenbug_Malware_4_RID2DFB : DEMO EXE FILE MAL MIDDLE_EAST {
   meta:
      description = "Detects ISMDoor Backdoor"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25 10:55:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f"
      hash2 = "82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
      tags = "DEMO, EXE, FILE, MAL, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "powershell.exe -nologo -windowstyle hidden -c \"Set-ExecutionPolicy -scope currentuser" fullword ascii
      $s2 = "powershell.exe -c \"Set-ExecutionPolicy -scope currentuser -ExecutionPolicy unrestricted -f; . \"" fullword ascii
      $s3 = "c:\\windows\\temp\\tmp8873" fullword ascii
      $s4 = "taskkill /im winit.exe /f" fullword ascii
      $s5 = "invoke-psuacme" 
      $s6 = "-method oobe -payload \"\"" fullword ascii
      $s7 = "C:\\ProgramData\\stat2.dat" fullword wide
      $s8 = "Invoke-bypassuac" fullword ascii
      $s9 = "Start Keylog Done" fullword wide
      $s10 = "Microsoft\\Windows\\WinIt.exe" fullword ascii
      $s11 = "Microsoft\\Windows\\Tmp9932u1.bat\"" fullword ascii
      $s12 = "Microsoft\\Windows\\tmp43hh11.txt" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them ) or ( 3 of them )
}

rule Shamoon2_Wiper_RID2C7E : APT DEMO EXE FILE MIDDLE_EAST {
   meta:
      description = "Detects Shamoon 2.0 Wiper Component"
      author = "Florian Roth"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01 09:51:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c7fc1f9c2bed748b50a599ee2fa609eb7c9ddaeb9cd16633ba0d10cf66891d8a"
      hash2 = "128fa5815c6fee68463b18051c1a1ccdf28c599ce321691686b1efa4838a2acd"
      tags = "APT, DEMO, EXE, FILE, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $a1 = "\\??\\%s\\System32\\%s.exe" fullword wide
      $x1 = "IWHBWWHVCIDBRAFUASIIWURRTWRTIBIVJDGWTRRREFDEAEBIAEBJGGCSVUHGVJUHADIEWAFGWADRUWDTJBHTSITDVVBCIDCWHRHVTDVCDESTHWSUAEHGTWTJWFIRTBRB" wide
      $s1 = "UFWYNYNTS" fullword wide
      $s2 = "\\\\?\\ElRawDisk" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them ) or ( 3 of them )
}

rule Shamoon2_ComComp_RID2D25 : APT DEMO EXE FILE MIDDLE_EAST T1083 {
   meta:
      description = "Detects Shamoon 2.0 Communication Components"
      author = "Florian Roth"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01 10:19:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "61c1c8fc8b268127751ac565ed4abd6bdab8d2d0f2ff6074291b2d54b0228842"
      tags = "APT, DEMO, EXE, FILE, MIDDLE_EAST, T1083"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "mkdir %s%s > nul 2>&1" fullword ascii
      $s2 = "p[%s%s%d.%s" fullword ascii
      $op1 = { 04 32 cb 88 04 37 88 4c 37 01 88 54 37 02 83 c6 } 
      $op2 = { c8 02 d2 c0 e9 06 02 d2 24 3f 02 d1 88 45 fb 8d } 
      $op3 = { 0c 3b 40 8d 4e 01 47 3b c1 7c d8 83 fe 03 7d 1c } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and ( all of ( $s* ) or all of ( $op* ) )
}

rule EldoS_RawDisk_RID2BFC : APT DEMO EXE FILE MIDDLE_EAST {
   meta:
      description = "EldoS Rawdisk Device Driver (Commercial raw disk access driver - used in Operation Shamoon 2.0)"
      author = "Florian Roth"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01 09:29:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-20"
      hash1 = "47bb36cd2832a18b5ae951cf5a7d44fba6d8f5dca0a372392d40f51d1fe1ac34"
      hash2 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"
      tags = "APT, DEMO, EXE, FILE, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "g\\system32\\" wide
      $s2 = "ztvttw" fullword wide
      $s3 = "lwizvm" fullword ascii
      $s4 = "FEJIKC" fullword ascii
      $s5 = "INZQND" fullword ascii
      $s6 = "IUTLOM" fullword wide
      $s7 = "DKFKCK" fullword ascii
      $op1 = { 94 35 77 73 03 40 eb e9 } 
      $op2 = { 80 7c 41 01 00 74 0a 3d } 
      $op3 = { 74 0a 3d 00 94 35 77 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 4 of them )
}

rule OilRig_Malware_Campaign_Gen1_RID31A8 : DEMO FILE G0049 MAL MIDDLE_EAST {
   meta:
      description = "Detects Oilrig malware samples"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12 13:31:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d808f3109822c185f1d8e1bf7ef7781c219dc56f5906478651748f0ace489d34"
      hash2 = "80161dad1603b9a7c4a92a07b5c8bce214cf7a3df897b561732f9df7920ecb3e"
      hash3 = "662c53e69b66d62a4822e666031fd441bbdfa741e20d4511c6741ec3cb02475f"
      tags = "DEMO, FILE, G0049, MAL, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "Get-Content $env:Public\\Libraries\\update.vbs) -replace" ascii
      $x2 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {waitfor haha /T 2}\" & Chr(34), 0" fullword ascii
      $x3 = "Call Extract(UpdateVbs, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\update.vbs\")" fullword ascii
      $s4 = "CreateObject(\"WScript.Shell\").Run cmd, 0o" fullword ascii
      $b1 = "JGdsb2JhbDpteWhvc3QgP" ascii
      $b2 = "SE9NRT0iJXB1YmxpYyVcTGlicmFyaWVzX" ascii
      $b3 = "U2V0IHdzcyA9IENyZWF0ZU9iamVjdCgid1NjcmlwdC5TaGV" ascii
      $b4 = "JHNjcmlwdGRpciA9IFNwbGl0LVBhdGggLVBhcmVudCAtUGF0aCA" ascii
      $b5 = "DQpTZXQgd3NzID0gQ3JlYXRlT2JqZWN" ascii
      $b6 = "d2hvYW1pICYgaG9zdG5hb" ascii
   condition: 
      ( uint16 ( 0 ) == 0xcfd0 and filesize < 700KB and 1 of them )
}

rule OilRig_Malware_Campaign_Mal1_RID31A8 : DEMO FILE G0049 MAL MIDDLE_EAST T1105 {
   meta:
      description = "Detects Oilrig malware samples"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12 13:31:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e17e1978563dc10b73fd54e7727cbbe95cc0b170a4e7bd0ab223e059f6c25fcc"
      tags = "DEMO, FILE, G0049, MAL, MIDDLE_EAST, T1105"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "DownloadExecute=\"powershell \"\"&{$r=Get-Random;$wc=(new-object System.Net.WebClient);$wc.DownloadFile(" ascii
      $x2 = "-ExecutionPolicy Bypass -File \"&HOME&\"dns.ps1\"" fullword ascii
      $x3 = "CreateObject(\"WScript.Shell\").Run Replace(DownloadExecute,\"-_\",\"bat\")" fullword ascii
      $x4 = "CreateObject(\"WScript.Shell\").Run DnsCmd,0" fullword ascii
      $s1 = "http://winodwsupdates.me" ascii
   condition: 
      ( uint16 ( 0 ) == 0x4f48 and filesize < 4KB and 1 of them ) or ( 2 of them )
}

rule OilRig_Malware_Campaign_Gen2_RID31A9 : DEMO FILE G0049 MAL MIDDLE_EAST T1053_005 {
   meta:
      description = "Detects Oilrig malware samples"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12 13:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-07"
      hash1 = "c6437f57a8f290b5ec46b0933bfa8a328b0cb2c0c7fbeea7f21b770ce0250d3d"
      hash2 = "293522e83aeebf185e653ac279bba202024cedb07abc94683930b74df51ce5cb"
      tags = "DEMO, FILE, G0049, MAL, MIDDLE_EAST, T1053_005"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "%userprofile%\\AppData\\Local\\Microsoft\\" ascii
      $s2 = "$fdn=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('" fullword ascii
      $s3 = "&{$rn = Get-Random; $id = 'TR" fullword ascii
      $s4 = "') -replace '__',('DNS'+$id) | " fullword ascii
      $s5 = "\\upd.vbs" ascii
      $s6 = "schtasks /create /F /sc minute /mo " fullword ascii
      $s7 = "') -replace '__',('HTP'+$id) | " fullword ascii
      $s8 = "&{$rn = Get-Random -minimum 1 -maximum 10000; $id = 'AZ" fullword ascii
      $s9 = "http://www.israirairlines.com/?mode=page&page=14635&lang=eng<" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xcfd0 and filesize < 4000KB and 2 of ( $s* ) ) or ( 4 of them )
}

rule OilRig_Malware_Campaign_Gen3_RID31AA : DEMO FILE G0049 MAL MIDDLE_EAST {
   meta:
      description = "Detects Oilrig malware samples"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12 13:32:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-07"
      hash1 = "5e9ddb25bde3719c392d08c13a295db418d7accd25d82d020b425052e7ba6dc9"
      hash2 = "bd0920c8836541f58e0778b4b64527e5a5f2084405f73ee33110f7bc189da7a9"
      hash3 = "90639c7423a329e304087428a01662cc06e2e9153299e37b1b1c90f6d0a195ed"
      tags = "DEMO, FILE, G0049, MAL, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "source code from https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.htmlrrrr" fullword ascii
      $x2 = "\\Libraries\\fireueye.vbs" ascii
      $x3 = "\\Libraries\\fireeye.vbs&" wide
   condition: 
      ( uint16 ( 0 ) == 0xcfd0 and filesize < 100KB and 1 of them )
}

rule OilRig_Malware_Campaign_Mal2_RID31A9 : DEMO FILE G0049 MAL MIDDLE_EAST {
   meta:
      description = "Detects Oilrig malware samples"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12 13:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "65920eaea00764a245acb58a3565941477b78a7bcc9efaec5bf811573084b6cf"
      tags = "DEMO, FILE, G0049, MAL, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {(Get-Content $env:Public\\Libraries\\update.vbs) -replace '__',(Get-Random) | Set-C" ascii
      $x2 = "Call Extract(UpdateVbs, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\update.vbs\")" fullword ascii
      $x3 = "mailto:Mohammed.sarah@gratner.com" fullword wide
      $x4 = "mailto:Tarik.Imam@gartner.com" fullword wide
      $x5 = "Call Extract(DnsPs1, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\dns.ps1\")" fullword ascii
      $x6 = "2dy53My5vcmcvMjAw" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0xcfd0 and filesize < 200KB and 1 of them )
}

rule OilRig_Campaign_Reconnaissance_RID32E1 : DEMO G0049 MAL MIDDLE_EAST T1016 T1033 T1087_002 {
   meta:
      description = "Detects Oilrig malware samples"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12 14:24:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5893eae26df8e15c1e0fa763bf88a1ae79484cdb488ba2fc382700ff2cfab80c"
      tags = "DEMO, G0049, MAL, MIDDLE_EAST, T1016, T1033, T1087_002"
      minimum_yara = "1.7"
      
   strings:
      $s1 = "whoami & hostname & ipconfig /all" ascii
      $s2 = "net user /domain 2>&1 & net group /domain 2>&1" ascii
      $s3 = "net group \"domain admins\" /domain 2>&1 & " ascii
   condition: 
      ( filesize < 1KB and 1 of them )
}

rule OilRig_Malware_Campaign_Mal3_RID31AA : DEMO G0049 MAL MIDDLE_EAST {
   meta:
      description = "Detects Oilrig malware samples"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12 13:32:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "02226181f27dbf59af5377e39cf583db15200100eea712fcb6f55c0a2245a378"
      tags = "DEMO, G0049, MAL, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "(Get-Content $env:Public\\Libraries\\dns.ps1) -replace ('#'+'##'),$botid | Set-Content $env:Public\\Libraries\\dns.ps1" fullword ascii
      $x2 = "Invoke-Expression ($global:myhome+'tp\\'+$global:filename+'.bat > '+$global:myhome+'tp\\'+$global:filename+'.txt')" fullword ascii
      $x3 = "('00000000'+(convertTo-Base36(Get-Random -Maximum 46655)))" fullword ascii
   condition: 
      ( filesize < 10KB and 1 of them )
}

rule MAL_APT_RocketKitten_Keylogger_RID326D : APT DEMO EXE FILE G0130 MAL MIDDLE_EAST T1056_001 {
   meta:
      description = "Detects Keylogger used in Rocket Kitten APT"
      author = "Florian Roth"
      reference = "https://goo.gl/SjQhlp"
      date = "2015-09-01 14:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1c9e519dca0468a87322bebe2a06741136de7969a4eb3efda0ab8db83f0807b4"
      hash2 = "495a15f9f30d6f6096a97c2bd8cc5edd4d78569b8d541b1d5a64169f8109bc5b"
      hash3 = "5dcc91911ea6c80508a2785ea94cce1f1a41b6362b094552e8494d655ea04e72"
      tags = "APT, DEMO, EXE, FILE, G0130, MAL, MIDDLE_EAST, T1056_001"
      minimum_yara = "1.7"
      
   strings:
      $x1 = "\\Release\\CWoolger.pdb" ascii
      $x2 = "WoolenLoger\\obj\\x86\\Release" ascii
      $x3 = "D:\\Yaser Logers\\" 
      $z1 = "woolger" fullword wide
      $s1 = "oShellLink.TargetPath = \"" fullword ascii
      $s2 = "wscript.exe " fullword ascii
      $s3 = "strSTUP = WshShell.SpecialFolders(\"Startup\")" fullword ascii
      $s4 = "[CapsLock]" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( 1 of ( $x* ) or ( $z1 and 2 of ( $s* ) ) ) ) or ( $z1 and all of ( $s* ) )
}

rule Explosion_Sample_1_RID2E23 : APT DEMO FILE G0123 MIDDLE_EAST T1112 {
   meta:
      description = "Explosion/Explosive Malware - Volatile Cedar APT"
      author = "Florian Roth"
      reference = "http://goo.gl/5vYaNb"
      date = "2015-04-03 11:01:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0123, MIDDLE_EAST, T1112"
      minimum_yara = "1.7"
      
   strings:
      $s5 = "REG ADD \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
      $s9 = "WinAutologon From Winlogon Reg" fullword ascii
      $s10 = "82BD0E67-9FEA-4748-8672-D5EFE5B779B0" fullword ascii
      $s11 = "IE:Password-Protected sites" fullword ascii
      $s12 = "\\his.sys" ascii
      $s13 = "HTTP Password" fullword ascii
      $s14 = "\\data.sys" ascii
      $s15 = "EL$_RasDefaultCredentials#0" fullword wide
      $s17 = "Office Outlook HTTP" fullword ascii
      $s20 = "Hist :<b> %ws</b>  :%s </br></br>" fullword ascii
   condition: 
      all of them and uint16 ( 0 ) == 0x5A4D
}

rule Explosion_Sample_2_RID2E24 : APT DEMO FILE G0123 MIDDLE_EAST {
   meta:
      description = "Explosion/Explosive Malware - Volatile Cedar APT"
      author = "Florian Roth"
      reference = "http://goo.gl/5vYaNb"
      date = "2015-04-03 11:01:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0123, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "serverhelp.dll" fullword wide
      $s1 = "Windows Help DLL" fullword wide
      $s5 = "SetWinHoK" fullword ascii
   condition: 
      all of them and uint16 ( 0 ) == 0x5A4D
}

rule Explosion_Generic_1_RID2E7E : APT DEMO FILE G0123 GEN MIDDLE_EAST T1091 {
   meta:
      description = "Generic Rule for Explosion/Explosive Malware - Volatile Cedar APT - Autorun"
      author = "Florian Roth"
      reference = "not set"
      date = "2015-04-03 11:16:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1952fa94b582e9af9dca596b5e51c585a78b8b1610639e3b878bbfa365e8e908"
      hash2 = "d8fdcdaad652c19f4f4676cd2f89ae834dbc19e2759a206044b18601875f2726"
      hash3 = "e2e6ed82703de21eb4c5885730ba3db42f3ddda8b94beb2ee0c3af61bc435747"
      tags = "APT, DEMO, FILE, G0123, GEN, MIDDLE_EAST, T1091"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "autorun.exe" fullword
      $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.1; .NET CL" 
      $s2 = "%drp.exe" fullword
      $s3 = "%s_%s%d.exe" fullword
      $s4 = "open=autorun.exe" fullword
      $s5 = "http://www.microsoft.com/en-us/default.aspx" fullword
      $s10 = "error.renamefile" fullword
      $s12 = "insufficient lookahead" fullword
      $s13 = "%s %s|" fullword
      $s16 = ":\\autorun.exe" fullword
   condition: 
      7 of them and uint16 ( 0 ) == 0x5A4D
}

rule CoreImpact_sysdll_exe_RID2F93 : APT DEMO G0130 MIDDLE_EAST {
   meta:
      description = "Detects a malware sysdll.exe from the Rocket Kitten APT"
      author = "Florian Roth"
      reference = "-"
      date = "2014-12-27 12:03:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "APT, DEMO, G0130, MIDDLE_EAST"
      minimum_yara = "1.7"
      
   strings:
      $s0 = "d:\\nightly\\sandbox_avg10_vc9_SP1_2011\\source\\avg10\\avg9_all_vs90\\bin\\Rele" ascii
      $s1 = "Mozilla/5.0" fullword ascii
      $s3 = "index.php?c=%s&r=%lx" fullword ascii
      $s4 = "index.php?c=%s&r=%x" fullword ascii
      $s5 = "127.0.0.1" fullword ascii
      $s6 = "/info.dat" ascii
      $s7 = "needroot" fullword ascii
      $s8 = "./plugins/" ascii
   condition: 
      $s0 or 6 of them
}