using System;
using System.Runtime.InteropServices;

namespace GetAPISetMapping
{
    class Helper
    {
        // API Defs
        //--------------------------------------
        [DllImport("ntdll.dll")]
        public static extern UInt32 RtlGetVersion(
            ref OSVERSIONINFOEX VersionInformation);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtQueryInformationProcess(
            IntPtr processHandle,
            UInt32 processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength,
            ref UInt32 returnLength);

        // Structs
        //--------------------------------------
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public int InheritedFromUniqueProcessId;

            public int Size
            {
                get { return (int)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OSVERSIONINFOEX
        {
            public uint OSVersionInfoSize;
            public uint MajorVersion;
            public uint MinorVersion;
            public uint BuildNumber;
            public uint PlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string CSDVersion;
            public ushort ServicePackMajor;
            public ushort ServicePackMinor;
            public ushort SuiteMask;
            public byte ProductType;
            public byte Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct ApiSetNamespace
        {
            [FieldOffset(0x0C)]
            public int Count;

            [FieldOffset(0x10)]
            public int EntryOffset;
        }

        [StructLayout(LayoutKind.Explicit, Size = 24)]
        public struct ApiSetNamespaceEntry
        {
            [FieldOffset(0x04)]
            public int NameOffset;

            [FieldOffset(0x08)]
            public int NameLength;

            [FieldOffset(0x10)]
            public int ValueOffset;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct ApiSetValueEntry
        {
            [FieldOffset(0x0C)]
            public int ValueOffset;

            [FieldOffset(0x10)]
            public int ValueCount;
        }

        // Helpers
        //--------------------------------------
        public static void PrintHelp()
        {
            string HelpText = " >--~~--> Args? <--~~--<\n\n" +
                              "-List   (-l)       Boolean: List all know API Set mappings.\n" +
                              "-Search (-s)       String: Perform string match based on partial or full API Set name.\n\n" +
                              " >--~~--> Usage? <--~~--<\n\n" +
                              "GetAPISetMapping.exe -l\n" +
                              "GetAPISetMapping.exe -s \"api-ms-win-appmodel-state-l1-2-0.dll\"";
            Console.WriteLine(HelpText);
        }
    }
}
