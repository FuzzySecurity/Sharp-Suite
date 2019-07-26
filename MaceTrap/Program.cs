using CommandLine;
using System;

namespace MaceTrap
{
    class Program
    {
        public static void SetObjectFileTime(String Path, String Time, Boolean CreateTime, Boolean AccessTime, Boolean WriteTime)
        {
            // Verify string time is valid datetime
            Mace.VALIDTIME td = Mace.VerifyStringTime(Time);
            if (!td.isValid)
            {
                Console.WriteLine("[!] Invalid DateTime string specified..");
                return;
            }

            Console.WriteLine("[+] Computed DateTime : " + td.dTime.ToString("MM/dd/yyyy hh:mm:ss.fff tt"));
            if (!CreateTime && !AccessTime && !WriteTime)
            {
                Console.WriteLine("[+] Stomping all FileTime fields..");
            } else
            {
                Console.WriteLine("[+] Stomping: CreationTime=" + CreateTime + " LastAccessTime=" + AccessTime + " LastWriteTime=" + WriteTime);
            }

            Boolean isStomp = Mace.SetTime(Path, td.dTime, CreateTime, AccessTime, WriteTime);
            if (isStomp)
            {
                Console.WriteLine("[+] Success, modified  : " + Path);
            } else
            {
                Console.WriteLine("[+] Failed to modify   : " + Path);
            }
        }

        public static void DuplicateObjectFileTime(String Target, String Source)
        {
            Console.WriteLine("[+] Reading source Filetime..");
            Mace.ALLDATETIME adt = Mace.GetTime(Source);
            if (!adt.isValid)
            {
                Console.WriteLine("[!] Unable to process source file..");
                return;
            }

            Console.WriteLine("\n[+] Stomping all FileTime fields..");
            Boolean isStomp = Mace.SetTime(Target, new DateTime(), false, false, false, adt);
            if (isStomp)
            {
                Console.WriteLine("[+] Success, modified  : " + Target);
            }
            else
            {
                Console.WriteLine("[+] Failed to modify   : " + Target);
            }
        }

        class ArgOptions
        {
            [Option("l", "List")]
            public string List { get; set; }

            [Option("s", "Set")]
            public string Set { get; set; }

            [Option("d", "Duplicate")]
            public string Duplicate { get; set; }

            [Option("t", "Time")]
            public string Time { get; set; }

            [Option("c", "Create")]
            public Boolean Create { get; set; }

            [Option("a", "Access")]
            public Boolean Access { get; set; }

            [Option("w", "Write")]
            public Boolean Write { get; set; }
        }

        static void Main(string[] args)
        {
            // Read args
            var ArgOptions = new ArgOptions();

            // Get that ASCII..
            Mace.PrintBanner();

            if (CommandLineParser.Default.ParseArguments(args, ArgOptions))
            {
                if (!string.IsNullOrEmpty(ArgOptions.List) || !string.IsNullOrEmpty(ArgOptions.Set))
                {

                    if (!string.IsNullOrEmpty(ArgOptions.List))
                    {
                        // Read timestamp information
                        Mace.GetTime(ArgOptions.List);
                    }
                    else if (!string.IsNullOrEmpty(ArgOptions.Duplicate))
                    {
                        DuplicateObjectFileTime(ArgOptions.Set, ArgOptions.Duplicate);
                    } else
                    {
                        if (!string.IsNullOrEmpty(ArgOptions.Time))
                        {
                            // Write timestamp information
                            SetObjectFileTime(ArgOptions.Set, ArgOptions.Time, ArgOptions.Create, ArgOptions.Access, ArgOptions.Write);
                        }
                        else
                        {
                            Console.WriteLine("[!] Missing DateTime string (-t)..");
                            return;
                        }
                    }
                }
                else
                {
                    Mace.PrintHelp();
                }
            }
            else
            {
                Mace.PrintHelp();
            }
        }
    }
}
