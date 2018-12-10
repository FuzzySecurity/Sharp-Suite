# Sharp-Suite

The king is dead, long live the king. I am starting a new repo with code samples in C#. My heart is still with PowerShell <3, lets face it using in-line C# in PowerShell is a much nicer experience than actually using C#! However, threat emulation has to evolve over time and so does the tooling.

## Pwn?

### SwampThing

SwampThing lets you to spoof process command line args (x32/64). Essentially you create a process in a suspended state, rewrite the PEB, resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones. Think for example about launching a wmic xsl stylesheet for code execution but faking an innocuous wmic command.

```
C:\>SwampThing.exe -l C:\Windows\System32\notepad.exe -f C:\aaa.txt -r C:\bbb.txt
      /
     :;                \
     |l      _____     |;
     `8o __-~     ~\   d|     Swamp
      "88p;.  -._\_;.oP         Thing
       `>,% (\  (\./)8"
      ,;%%%:  ./V^^^V'
;;;,-::::::'_::\   ||\
8888oooooo.  :\`^^^/,,~--._
 oo.8888888888:`((( o.ooo888
   `o`88888888b` )) 888b8888
     b`888888888;(.,"888b888\
....  b`8888888:::::.`8888.
 `:::. `:::OOO:::::::.`OO' ;
   `.      "``::::::''.'        ~ b33f ~

[>] CreateProcess -> Suspended
[+] PE Arch                       : 64-bit
[+] Process Id                    : 10568
[+] PEB Base                      : 0xA3C2431000
[+] RTL_USER_PROCESS_PARAMETERS   : 0x20DA9760000
[+] CommandLine                   : 0x20DA9760070
[+] UNICODE_STRING |-> Len        : 66
                   |-> MaxLen     : 68
                   |-> pBuff      : 0x20DA9760658

[>] Rewrite -> RTL_USER_PROCESS_PARAMETERS
[+] RtlCreateProcessParametersEx  : 0xEAADF0
[+] RemoteAlloc                   : 0xEA0000
[+] Size                          : 1776
[?] Success, sleeping 500ms..

[>] Reverting RTL_USER_PROCESS_PARAMETERS
[+] Local UNICODE_STRING          : 0xEBC4D0
[+] Remote UNICODE_STRING.Buffer  : 0x20DA9B10000
[+] pRTL_USER_PROCESS_PARAMETERS  : 0x20DA9870FE0
[?] Success rewrote Len, MaxLen, Buffer..
```