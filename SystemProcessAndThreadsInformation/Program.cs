using System;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using Colorful;
using Console = Colorful.Console;
using System.Drawing;

namespace SystemProcessAndThreadsInformation
{
    class SPTI
    {
        // Global vars
        //===================
        public static int LoopSize = 0;
        public static int SystemInformationLength = 0;
        public static IntPtr BuffPtr = IntPtr.Zero;
        public static IntPtr SeekPtr = IntPtr.Zero;
        public static Formatter[] pProperties = 
        {
            new Formatter("[>]", Color.LightGreen),
            new Formatter(":", Color.LightGreen),
            new Formatter("ImageName          ", Color.Orange),
            new Formatter("ProcessId          ", Color.Orange),
            new Formatter("ParentPid          ", Color.Orange),
            new Formatter("HandleCount        ", Color.Orange),
            new Formatter("ThreadCount        ", Color.Orange),
            new Formatter("SessionId          ", Color.Orange),
            new Formatter("Priority           ", Color.Orange),
            new Formatter("CreateTime         ", Color.Orange),
            new Formatter("UserTime           ", Color.Orange),
            new Formatter("KernelTime         ", Color.Orange),
            new Formatter("WorkingSetSize     ", Color.Orange),
            new Formatter("PeakWorkingSetSize ", Color.Orange),
            new Formatter("PageFaultCount     ", Color.Orange),
        };
        public static Formatter[] tProperties =
        {
            new Formatter("[>]", Color.LightGreen),
            new Formatter(":", Color.LightGreen),
            new Formatter("|->", Color.LightGreen),
            new Formatter("TID", Color.Orange),
            new Formatter("Priority", Color.Orange),
            new Formatter("StartAddress", Color.Orange),
            new Formatter("Created", Color.Orange),
            new Formatter("uTime", Color.Orange),
            new Formatter("kTime", Color.Orange),
            new Formatter("WaitTime", Color.Orange),
            new Formatter("WaitReason", Color.Orange),
            new Formatter("State", Color.Orange),
            new Formatter("ContextSwitches", Color.Orange),
            new Formatter(",", Color.LightGreen),
        };

        // Enums
        //===================
        public enum KWAIT_REASON
        {
            Executive,
            FreePage,
            PageIn,
            PoolAllocation,
            DelayExecution,
            Suspended,
            UserRequest,
            WrExecutive,
            WrFreePage,
            WrPageIn,
            WrPoolAllocation,
            WrDelayExecution,
            WrSuspended,
            WrUserRequest,
            WrEventPair,
            WrQueue,
            WrLpcReceive,
            WrLpcReply,
            WrVirtualMemory,
            WrPageOut,
            WrRendezvous,
            Spare2,
            Spare3,
            Spare4,
            Spare5,
            WrCalloutStack,
            WrKernel,
            WrResource,
            WrPushLock,
            WrMutex,
            WrQuantumEnd,
            WrDispatchInt,
            WrPreempted,
            WrYieldExecution,
            WrFastMutex,
            WrGuardedMutex,
            WrRundown,
            MaximumWaitReason
        }

        public enum THREAD_STATE
        {
            Initialized,
            Ready,
            Running,
            Standby,
            Terminated,
            Wait,
            Transition,
            Unknown
        }

        // Structs
        //===================
        [StructLayout(LayoutKind.Sequential)]
        public struct LARGE_INTEGER
        {
            public UInt32 LowPart;
            public UInt32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
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
        public struct SYSTEM_THREAD_INFORMATION
        {
            public long KernelTime;
            public long UserTime;
            public long CreateTime;
            public uint WaitTime;
            public IntPtr StartAddress;
            public CLIENT_ID ClientId;
            public int Priority;
            public int BasePriority;
            public uint ContextSwitchCount;
            public THREAD_STATE State;
            public KWAIT_REASON WaitReason;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_PROCESSES
        {
            public int NextEntryOffset;
            public int NumberOfThreads;
            public LARGE_INTEGER WorkingSetPrivateSize;
            public uint HardFaultCount;
            public uint NumberOfThreadsHighWatermark;
            public ulong CycleTime;
            public long CreateTime;
            public long UserTime;
            public long KernelTime;
            public UNICODE_STRING ImageName;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
            public int HandleCount;
            public int SessionId;
            public IntPtr UniqueProcessKey;
            public IntPtr PeakVirtualSize;
            public IntPtr VirtualSize;
            public uint PageFaultCount;
            public IntPtr PeakWorkingSetSize;
            public IntPtr WorkingSetSize;
            public IntPtr QuotaPeakPagedPoolUsage;
            public IntPtr QuotaPagedPoolUsage;
            public IntPtr QuotaPeakNonPagedPoolUsage;
            public IntPtr QuotaNonPagedPoolUsage;
            public IntPtr PagefileUsage;
            public IntPtr PeakPagefileUsage;
            public IntPtr PrivatePageCount;
            public LARGE_INTEGER ReadOperationCount;
            public LARGE_INTEGER WriteOperationCount;
            public LARGE_INTEGER OtherOperationCount;
            public LARGE_INTEGER ReadTransferCount;
            public LARGE_INTEGER WriteTransferCount;
            public LARGE_INTEGER OtherTransferCount;
        }

        // API's
        //===================
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtQuerySystemInformation(
                int SystemInformationClass,
                IntPtr SystemInformation,
                int SystemInformationLength,
                ref int ReturnLength);

        // Helpers
        //===================
        public static object GetThreadInformation(UInt32 ProcId)
        {
            // We loop till success or error out
            while (true)
            {
                BuffPtr = Marshal.AllocHGlobal(LoopSize);
                UInt32 CallResult = NtQuerySystemInformation(0x5, BuffPtr, LoopSize, ref SystemInformationLength); // 0x5 = SystemProcessAndThreadInformation

                if (CallResult == 0xC0000004)
                {
                    Marshal.FreeHGlobal(BuffPtr);
                    LoopSize = Math.Max(LoopSize, SystemInformationLength);
                }
                else if (CallResult == 0x00000000)
                {
                    break;
                }
                else
                {
                    Marshal.FreeHGlobal(BuffPtr);
                    return false;
                }
            }

            // Duplicate BuffPtr so we can seek on the data
            SeekPtr = BuffPtr;

            // Seek result data
            while (true)
            {
                var SysProcess = (SYSTEM_PROCESSES)Marshal.PtrToStructure(SeekPtr, typeof(SYSTEM_PROCESSES));
                if (SysProcess.UniqueProcessId == (IntPtr)ProcId)
                {
                    // Grab process details
                    Console.WriteLine("\n[+] Process Details", Color.LightGreen);
                    Console.WriteLineFormatted("    {2} {1} " + Marshal.PtrToStringUni(SysProcess.ImageName.Buffer), Color.White, pProperties);
                    Console.WriteLineFormatted("    {3} {1} " + SysProcess.UniqueProcessId, Color.White, pProperties);
                    Console.WriteLineFormatted("    {4} {1} " + SysProcess.InheritedFromUniqueProcessId, Color.White, pProperties);
                    Console.WriteLineFormatted("    {5} {1} " + SysProcess.HandleCount, Color.White, pProperties);
                    Console.WriteLineFormatted("    {6} {1} " + SysProcess.NumberOfThreads, Color.White, pProperties);
                    Console.WriteLineFormatted("    {7} {1} " + SysProcess.SessionId, Color.White, pProperties);
                    Console.WriteLineFormatted("    {8} {1} " + SysProcess.BasePriority, Color.White, pProperties);
                    Console.WriteLineFormatted("    {9} {1} " + DateTime.FromBinary(SysProcess.CreateTime).TimeOfDay.Days + "d:" + DateTime.FromBinary(SysProcess.CreateTime).TimeOfDay.Hours + "h:" + DateTime.FromBinary(SysProcess.CreateTime).TimeOfDay.Minutes + "m:" + DateTime.FromBinary(SysProcess.CreateTime).TimeOfDay.Seconds + "s:" + DateTime.FromBinary(SysProcess.CreateTime).TimeOfDay.Milliseconds + "ms", Color.White, pProperties);
                    Console.WriteLineFormatted("    {10} {1} " + DateTime.FromBinary(SysProcess.UserTime).TimeOfDay.Days + "d:" + DateTime.FromBinary(SysProcess.UserTime).TimeOfDay.Hours + "h:" + DateTime.FromBinary(SysProcess.UserTime).TimeOfDay.Minutes + "m:" + DateTime.FromBinary(SysProcess.UserTime).TimeOfDay.Seconds + "s:" + DateTime.FromBinary(SysProcess.UserTime).TimeOfDay.Milliseconds + "ms", Color.White, pProperties);
                    Console.WriteLineFormatted("    {11} {1} " + DateTime.FromBinary(SysProcess.KernelTime).TimeOfDay.Days + "d:" + DateTime.FromBinary(SysProcess.KernelTime).TimeOfDay.Hours + "h:" + DateTime.FromBinary(SysProcess.KernelTime).TimeOfDay.Minutes + "m:" + DateTime.FromBinary(SysProcess.KernelTime).TimeOfDay.Seconds + "s:" + DateTime.FromBinary(SysProcess.KernelTime).TimeOfDay.Milliseconds + "ms", Color.White, pProperties);
                    Console.WriteLineFormatted("    {12} {1} " + (SysProcess.WorkingSetSize.ToInt64() / Math.Pow(1024,2)) + " MB", Color.White, pProperties);
                    Console.WriteLineFormatted("    {13} {1} " + (SysProcess.PeakWorkingSetSize.ToInt64() / Math.Pow(1024, 2)) + " MB", Color.White, pProperties);
                    Console.WriteLineFormatted("    {14} {1} " + SysProcess.PageFaultCount, Color.White, pProperties);

                    // Move Ptr to thread array & grab thread details
                    Console.WriteLine("\n[+] Thread Details", Color.LightGreen);
                    SeekPtr = new IntPtr(Marshal.SizeOf(typeof(SYSTEM_PROCESSES)) + SeekPtr.ToInt64());
                    for (int i = 0; i < SysProcess.NumberOfThreads; i++)
                    {
                        var ThreadPtr = (SYSTEM_THREAD_INFORMATION)Marshal.PtrToStructure(SeekPtr, typeof(SYSTEM_THREAD_INFORMATION));
                        var TID = ThreadPtr.ClientId.UniqueThread;
                        var Priority = ThreadPtr.Priority;
                        var StartAddress = "0x" + String.Format("{0:X}", (ThreadPtr.StartAddress).ToInt64());
                        var Created = DateTime.FromBinary(ThreadPtr.CreateTime).TimeOfDay.Days + "d:" + DateTime.FromBinary(ThreadPtr.CreateTime).TimeOfDay.Hours + "h:" + DateTime.FromBinary(ThreadPtr.CreateTime).TimeOfDay.Minutes + "m:" + DateTime.FromBinary(ThreadPtr.CreateTime).TimeOfDay.Seconds + "s:" + DateTime.FromBinary(ThreadPtr.CreateTime).TimeOfDay.Milliseconds + "ms";
                        var uTime = DateTime.FromBinary(ThreadPtr.UserTime).TimeOfDay.Days + "d:" + DateTime.FromBinary(ThreadPtr.UserTime).TimeOfDay.Hours + "h:" + DateTime.FromBinary(ThreadPtr.UserTime).TimeOfDay.Minutes + "m:" + DateTime.FromBinary(ThreadPtr.UserTime).TimeOfDay.Seconds + "s:" + DateTime.FromBinary(ThreadPtr.UserTime).TimeOfDay.Milliseconds + "ms";
                        var kTime = DateTime.FromBinary(ThreadPtr.KernelTime).TimeOfDay.Days + "d:" + DateTime.FromBinary(ThreadPtr.KernelTime).TimeOfDay.Hours + "h:" + DateTime.FromBinary(ThreadPtr.KernelTime).TimeOfDay.Minutes + "m:" + DateTime.FromBinary(ThreadPtr.KernelTime).TimeOfDay.Seconds + "s:" + DateTime.FromBinary(ThreadPtr.KernelTime).TimeOfDay.Milliseconds + "ms";
                        var WaitTime = ThreadPtr.WaitTime;
                        var WaitReason = ThreadPtr.WaitReason;
                        var State = ThreadPtr.State;
                        var ContextSwitches = ThreadPtr.ContextSwitchCount;

                        Console.WriteLineFormatted("{0} {3}{1} " + TID + "{13} {4}{1} " + Priority, Color.White, tProperties);
                        Console.WriteLineFormatted("    {2} {5}{1} " + StartAddress, Color.White, tProperties);
                        Console.WriteLineFormatted("    {2} {6}{1} " + Created + "{13} {7}{1} " + uTime + "{13} {8}{1} " + kTime, Color.White, tProperties);
                        Console.WriteLineFormatted("    {2} {9}{1} " + WaitTime + "{13} {10}{1} " + WaitReason, Color.White, tProperties);
                        Console.WriteLineFormatted("    {2} {11}{1} " + State + "{13} {12}{1} " + ContextSwitches + "\n", Color.White, tProperties);

                        SeekPtr = new IntPtr(Marshal.SizeOf(typeof(SYSTEM_THREAD_INFORMATION)) + SeekPtr.ToInt64());

                    }
                    break;
                }
                else if (Marshal.ReadInt32(SeekPtr) == 0)
                {
                    Console.WriteLine("[!] Process ID not found..", Color.Red);
                    break;
                }
                else
                {
                    SeekPtr = new IntPtr(Marshal.ReadInt32(SeekPtr) + SeekPtr.ToInt64());
                }
            }
            // Free BuffPtr
            Marshal.FreeHGlobal(BuffPtr);
            return true;
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("[!] Please specify a process id (-p|--ProcId)", Color.Red);
            }
            else
            {
                int ProcId = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(p|ProcId)$").Match(s).Success);
                if (ProcId != -1)
                {
                    try
                    {
                        UInt32 Proc = uint.Parse(args[(ProcId + 1)]);
                        GetThreadInformation(Proc);
                    } catch
                    {
                        Console.WriteLine("[!] Please specify a valid process id (-p|--ProcId)", Color.Red);
                        return;
                    }
                }
                else
                {
                    Console.WriteLine("[!] Please specify a process id (-p|--ProcId)", Color.Red);
                }
            }
        }

    }
}
