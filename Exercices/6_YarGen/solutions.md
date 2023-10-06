```sh
└─kali㉿kali-[~/Yara_rules_tp/Exercices/yarGen]
└─$ python3 yarGen.py -m ../YarGen/MaybeMalicious/ -o test.yara 
------------------------------------------------------------------------
                   _____            
    __ _____ _____/ ___/__ ___      
   / // / _ `/ __/ (_ / -_) _ \     
   \_, /\_,_/_/  \___/\__/_//_/     
  /___/  Yara Rule Generator        
         Florian Roth, August 2023, Version 0.24.0
   
  Note: Rules have to be post-processed
  See this post for details: https://medium.com/@cyb3rops/121d29322282
------------------------------------------------------------------------
[+] Using identifier 'MaybeMalicious'
[+] Using reference 'https://github.com/Neo23x0/yarGen'
[+] Using prefix 'MaybeMalicious'
[+] Processing PEStudio strings ...
[+] Reading goodware strings from database 'good-strings.db' ...
    (This could take some time and uses several Gigabytes of RAM depending on your db size)
[+] Loading ./dbs/good-exports-part9.db ...
[+] Total: 0 / Added 0 entries
[+] Loading ./dbs/good-exports-part3.db ...
[+] Total: 117975 / Added 117975 entries
[+] Loading ./dbs/good-imphashes-part2.db ...
[+] Total: 1056 / Added 1056 entries
[+] Loading ./dbs/good-imphashes-part6.db ...
[+] Total: 1087 / Added 31 entries
[+] Loading ./dbs/good-exports-part2.db ...
[+] Total: 187777 / Added 69802 entries
[+] Loading ./dbs/good-imphashes-part3.db ...
[+] Total: 4908 / Added 3821 entries
[+] Loading ./dbs/good-imphashes-part7.db ...
[+] Total: 8479 / Added 3571 entries
[+] Loading ./dbs/good-imphashes-part9.db ...
[+] Total: 8479 / Added 0 entries
[+] Loading ./dbs/good-exports-part1.db ...
[+] Total: 263379 / Added 75602 entries
[+] Loading ./dbs/good-exports-part7.db ...
[+] Total: 312077 / Added 48698 entries
[+] Loading ./dbs/good-strings-part5.db ...
[+] Total: 4230341 / Added 4230341 entries
[+] Loading ./dbs/good-imphashes-part5.db ...
[+] Total: 15649 / Added 7170 entries
[+] Loading ./dbs/good-imphashes-part4.db ...
[+] Total: 18025 / Added 2376 entries
[+] Loading ./dbs/good-exports-part6.db ...
[+] Total: 313736 / Added 1659 entries
[+] Loading ./dbs/good-strings-part3.db ...
[+] Total: 7075535 / Added 2845194 entries
[+] Loading ./dbs/good-strings-part6.db ...
[+] Total: 7696316 / Added 620781 entries
[+] Loading ./dbs/good-imphashes-part1.db ...
[+] Total: 19581 / Added 1556 entries
[+] Loading ./dbs/good-exports-part4.db ...
[+] Total: 328525 / Added 14789 entries
[+] Loading ./dbs/good-strings-part2.db ...
[+] Total: 8777781 / Added 1081465 entries
[+] Loading ./dbs/good-exports-part8.db ...
[+] Total: 332359 / Added 3834 entries
[+] Loading ./dbs/good-imphashes-part8.db ...
[+] Total: 19764 / Added 183 entries
[+] Loading ./dbs/good-strings-part4.db ...
[+] Total: 10168982 / Added 1391201 entries
[+] Loading ./dbs/good-strings-part8.db ...
[+] Total: 10420040 / Added 251058 entries
[+] Loading ./dbs/good-strings-part7.db ...
[+] Total: 11280784 / Added 860744 entries
[+] Loading ./dbs/good-exports-part5.db ...
[+] Total: 404321 / Added 71962 entries
[+] Loading ./dbs/good-strings-part1.db ...
[+] Total: 12284223 / Added 1003439 entries
[+] Loading ./dbs/good-strings-part9.db ...
[+] Total: 12284943 / Added 720 entries
[+] Processing malware files ...
[+] Processing ../YarGen/MaybeMalicious/testshellcode ...
[+] Processing ../YarGen/MaybeMalicious/Reverseshellcode.exe ...
[+] Generating statistical data ...
[+] Generating Super Rules ... (a lot of magic)
[+] Generating Simple Rules ...
[-] Applying intelligent filters to string findings ...
[-] Filtering string set for ../YarGen/MaybeMalicious/testshellcode ...
[-] Filtering string set for ../YarGen/MaybeMalicious/Reverseshellcode.exe ...
[+] Generating Super Rules ...
[=] Generated 2 SIMPLE rules.
[=] Generated 0 SUPER rules.
[=] All rules written to test.yara
[+] yarGen run finished
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Yara_rules_tp/Exercices/yarGen]
└─$ ls
3rdparty  dbs  LICENSE  prepare-release.sh  README.md  requirements.txt  screens  test.yara  tools  yarGen.py
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Yara_rules_tp/Exercices/yarGen]
└─$ cat test.yara            
/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-09-22
   Identifier: MaybeMalicious
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule testshellcode {
   meta:
      description = "MaybeMalicious - file testshellcode"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-09-22"
      hash1 = "dd00e7e3b0534ae031b0d0d782141b32d71b4a806f8a2da1696ee7fe343fddc8"
   strings:
      $s1 = "Shellcode Length:  %d" fullword ascii
      $s2 = ".note.ABI-tag" fullword ascii
      $s3 = "completed.0" fullword ascii
      $s4 = ".note.gnu.build-id" fullword ascii
      $s5 = ".note.gnu.property" fullword ascii
      $s6 = "__GNU_EH_FRAME_HDR" fullword ascii
      $s7 = "frame_dummy" fullword ascii
      $s8 = "__frame_dummy_init_array_entry" fullword ascii
      $s9 = "__FRAME_END__" fullword ascii
      $s10 = "_IO_stdin_used" fullword ascii
      $s11 = ".eh_frame_hdr" fullword ascii
      $s12 = "whoami" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "deregister_tm_clones" fullword ascii
      $s14 = "GLIBC_2.2.5" fullword ascii
      $s15 = "__libc_start_main@GLIBC_2.34" fullword ascii
      $s16 = "printf@GLIBC_2.2.5" fullword ascii
      $s17 = "/lib64/ld-linux-x86-64.so.2" fullword ascii
      $s18 = "strlen@GLIBC_2.2.5" fullword ascii
      $s19 = "__libc_start_main" fullword ascii
      $s20 = "libc.so.6" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 50KB and
      8 of them
}

rule Reverseshellcode {
   meta:
      description = "MaybeMalicious - file Reverseshellcode.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-09-22"
      hash1 = "3c93f0ca54ee4acafc0bb34a8b5404c0d04798090b42447d33e390fe01159dcc"
   strings:
      $s1 = "C:\\local0\\asf\\release\\build-2.2.14\\support\\Release\\ab.pdb" fullword ascii
      $s2 = " Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/<br>" fullword ascii
      $s3 = "    -T content-type Content-type header for POSTing, eg." fullword ascii
      $s4 = "    -i              Use HEAD instead of GET" fullword ascii
      $s5 = "    -p postfile     File containing data to POST. Remember also to set -T" fullword ascii
      $s6 = "    -h              Display usage information (this message)" fullword ascii
      $s7 = " Licensed to The Apache Software Foundation, http://www.apache.org/<br>" fullword ascii
      $s8 = "    -k              Use HTTP KeepAlive feature" fullword ascii
      $s9 = " This is ApacheBench, Version %s <i>&lt;%s&gt;</i><br>" fullword ascii
      $s10 = "    -r              Don't exit on socket receive errors." fullword ascii
      $s11 = "    -X proxy:port   Proxyserver and port number to use" fullword ascii
      $s12 = "  %d%%  %5I64d" fullword ascii
      $s13 = "    -H attribute    Add Arbitrary header line, eg. 'Accept-Encoding: gzip'" fullword ascii
      $s14 = "                    are a colon separated username and password." fullword ascii
      $s15 = "    -e filename     Output CSV file with percentages served" fullword ascii
      $s16 = "    -d              Do not show percentiles served table." fullword ascii
      $s17 = "    -b windowsize   Size of TCP send/receive buffer, in bytes" fullword ascii
      $s18 = "    -w              Print out results in HTML tables" fullword ascii
      $s19 = "    -n requests     Number of requests to perform" fullword ascii
      $s20 = "    -t timelimit    Seconds to max. wait for responses" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

```