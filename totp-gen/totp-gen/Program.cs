using System;
using CommandLine;

namespace totp_gen
{
    internal class Program
    {
        public static void generateTOTP(String sSeed)
        {
            hTOTP.TOTP oTotp = hTOTP.generateTOTP(sSeed);
            Console.WriteLine("[+] TOTP valid for {0} seconds", oTotp.Seconds);
            Console.WriteLine("[>] TOTP code --> {0}", oTotp.Code);
        }

        public static void checkTOTP(String sSeed, UInt32 iCode)
        {
            Boolean bTOTP = hTOTP.validateTOTP(sSeed, iCode);
            if (bTOTP)
            {
                Console.WriteLine("[+] TOTP code is valid");
            }
            else
            {
                Console.WriteLine("[!] TOTP code is invalid");
            }
        }
        
        class ArgOptions
        {
            [Option("s", "seed")]
            public String Seed { get; set; }

            [Option("c", "code")]
            public UInt32 Code { get; set; }
        }
        
        public static void Main(string[] args)
        {
            hTOTP.printBanner();
            
            ArgOptions ArgOptions = new ArgOptions();
            if (CommandLineParser.Default.ParseArguments(args, ArgOptions))
            {
                if (!String.IsNullOrEmpty(ArgOptions.Seed))
                {
                    if (ArgOptions.Code != 0)
                    {
                        checkTOTP(ArgOptions.Seed, ArgOptions.Code);
                    }
                    else
                    {
                        generateTOTP(ArgOptions.Seed);
                    }
                }
                else
                {
                    hTOTP.getHelp();
                }

            }
            else
            {
                hTOTP.getHelp();
            }
        }
    }
}