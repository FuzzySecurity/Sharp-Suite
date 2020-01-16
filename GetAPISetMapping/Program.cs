using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using CommandLine;

namespace GetAPISetMapping
{
    class Program
    {
        public static Dictionary<string, string> GetApiSetDict()
        {
            // Get PEB
            Helper.PROCESS_BASIC_INFORMATION pbi = new Helper.PROCESS_BASIC_INFORMATION();
            UInt32 RetLen = 0;
            Helper.NtQueryInformationProcess((IntPtr)(-1), 0, ref pbi, Marshal.SizeOf(pbi), ref RetLen);

            // Are we executing for x86 or x64
            UInt32 ApiSetMapOffset = 0;
            if (IntPtr.Size == 4)
            {
                ApiSetMapOffset = 0x38;
            }
            else
            {
                ApiSetMapOffset = 0x68;
            }

            // Create mapping dictionary
            Dictionary<string, string> ApiSetDict = new Dictionary<string, string>();

            IntPtr pApiSetNamespace = Marshal.ReadIntPtr((IntPtr)((UInt64)pbi.PebBaseAddress + ApiSetMapOffset));
            Helper.ApiSetNamespace Namespace = new Helper.ApiSetNamespace();
            Namespace = (Helper.ApiSetNamespace)Marshal.PtrToStructure(pApiSetNamespace, typeof(Helper.ApiSetNamespace));
            for (var i = 0; i < Namespace.Count; i++)
            {
                Helper.ApiSetNamespaceEntry SetEntry = new Helper.ApiSetNamespaceEntry();
                SetEntry = (Helper.ApiSetNamespaceEntry)Marshal.PtrToStructure((IntPtr)((UInt64)pApiSetNamespace + (UInt64)Namespace.EntryOffset + (UInt64)(i * Marshal.SizeOf(SetEntry))), typeof(Helper.ApiSetNamespaceEntry));
                String ApiSetEntryName = Marshal.PtrToStringUni((IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetEntry.NameOffset), SetEntry.NameLength / 2) + ".dll";

                Helper.ApiSetValueEntry SetValue = new Helper.ApiSetValueEntry();
                SetValue = (Helper.ApiSetValueEntry)Marshal.PtrToStructure((IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetEntry.ValueOffset), typeof(Helper.ApiSetValueEntry));
                String ApiSetValue = String.Empty;
                if (SetValue.ValueCount != 0)
                {
                    ApiSetValue = Marshal.PtrToStringUni((IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetValue.ValueOffset), SetValue.ValueCount / 2);

                }

                // Add pair to dict
                ApiSetDict.Add(ApiSetEntryName, ApiSetValue);
            }

            // Return dict
            return ApiSetDict;
        }

        // Read API set
        public static void GetAPISet(String Name, Boolean List)
        {
            // Our parser only supports resolution on the Win10 PEB format
            Helper.OSVERSIONINFOEX ovi = new Helper.OSVERSIONINFOEX();
            Helper.RtlGetVersion(ref ovi);
            if (ovi.MajorVersion != 10)
            {
                Console.WriteLine("API Set resolution is only supported on Windows 10..");
                return;
            }

            Dictionary<string, string> ApiDict = GetApiSetDict();
            if (List)
            {
                foreach (KeyValuePair<string, string> mapping in ApiDict)
                {
                    if (string.IsNullOrEmpty(mapping.Value))
                    {
                        Console.WriteLine("API Set: " + mapping.Key + "  -->  N/A");
                    } else
                    {
                        Console.WriteLine("API Set: " + mapping.Key + "  -->  " + mapping.Value);
                    }
                }
            } else
            {
                String SearchResult = String.Empty;
                foreach (KeyValuePair<string, string> mapping in ApiDict)
                {
                    if ((mapping.Key).ToLower().Contains(Name.ToLower()))
                    {
                        if (SearchResult == String.Empty)
                        {
                            if (string.IsNullOrEmpty(mapping.Value))
                            {
                                SearchResult += "API Set: " + mapping.Key + "  -->  N/A";
                            }
                            else
                            {
                                SearchResult += "API Set: " + mapping.Key + "  -->  " + mapping.Value;
                            }
                        } else
                        {
                            if (string.IsNullOrEmpty(mapping.Value))
                            {
                                SearchResult += "\nAPI Set: " + mapping.Key + "  -->  N/A";
                            }
                            else
                            {
                                SearchResult += "\nAPI Set: " + mapping.Key + "  -->  " + mapping.Value;
                            }
                        }
                    }
                }

                if (SearchResult == String.Empty)
                {
                    Console.WriteLine("[!] No matches found..");
                } else
                {
                    Console.WriteLine(SearchResult);
                }
            }
        }

        // Process arg options
        class ArgOptions
        {
            [Option("s", "Search")]
            public string Search { get; set; }

            [Option("l", "List")]
            public bool List { get; set; }
        }

        static void Main(string[] args)
        {
            // Read args
            var ArgOptions = new ArgOptions();

            // Parse args
            if (CommandLineParser.Default.ParseArguments(args, ArgOptions))
            {
                if (string.IsNullOrEmpty(ArgOptions.Search) && !ArgOptions.List)
                {
                     Helper.PrintHelp();
                }
                else
                {
                     if (ArgOptions.List)
                     {
                         GetAPISet(String.Empty, true);
                     } else
                     {
                         GetAPISet(ArgOptions.Search, false);
                     }
                }
            }
            else
            {
                Helper.PrintHelp();
            }
        }
    }
}
