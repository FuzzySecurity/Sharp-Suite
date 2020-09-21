using CommandLine;
using System;
using System.Collections.Generic;
using System.IO;

namespace FinchGen
{
    class Program
    {
        public static Boolean CreateTemplate(String Path, String Key, String Out)
        {
            List<Byte[]> lCompList = Helper.GzipCompressFileToArray(Path);
            if (lCompList.Count < 2)
            {
                Console.WriteLine("[!] Failed to b64 Compress file..");
                return false;
            }

            String b64Keyed = Helper.AESKeyToB64(lCompList[1], Key);
            if (String.IsNullOrEmpty(b64Keyed))
            {
                Console.WriteLine("[!] Failed to key b64..");
                return false;
            }

            try
            {
                File.WriteAllText(Out, string.Format(Helper.PayloadConfig, Convert.ToBase64String(lCompList[0]), b64Keyed));
                Console.WriteLine("[+] Success, created keyed csharp template!");
                return true;
            }
            catch
            {
                Console.WriteLine("[!] Failed to write payload template to disk..");
                Console.WriteLine("    |-> Did you provide a full, valid file path?");
                return false;
            }
        }

        class ArgOptions
        {
            [Option("p", "Path")]
            public string Path { get; set; }

            [Option("o", "Out")]
            public string Out { get; set; }

            [Option("k", "Key")]
            public string Key { get; set; }
        }

        static void Main(string[] args)
        {
            // Read args
            var ArgOptions = new ArgOptions();

            // Parse args
            if (CommandLineParser.Default.ParseArguments(args, ArgOptions))
            {
                if (!string.IsNullOrEmpty(ArgOptions.Path) || !string.IsNullOrEmpty(ArgOptions.Key) || !string.IsNullOrEmpty(ArgOptions.Out))
                {
                    CreateTemplate(ArgOptions.Path, ArgOptions.Key, ArgOptions.Out);
                }
                else
                {
                    Console.WriteLine("[!] Failed to provide args (-p|-Path & -k|-Key  & -o|-Out)");
                }
            }
            else
            {
                Console.WriteLine("[!] Failed to provide args (-p|-Path & -k|-Key  & -o|-Out)");
            }
        }
    }
}
