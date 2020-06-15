using System;

namespace VirtToPhys
{
	class hSupp
	{
        public static void PrintBanner()
		{
            Console.WriteLine(@" _   _ _      _ _____    ______ _               ");
            Console.WriteLine(@"| | | (_)    | |_   _|   | ___ \ |              ");
            Console.WriteLine(@"| | | |_ _ __| |_| | ___ | |_/ / |__  _   _ ___ ");
            Console.WriteLine(@"| | | | | '__| __| |/ _ \|  __/| '_ \| | | / __|");
            Console.WriteLine(@"\ \_/ / | |  | |_| | (_) | |   | | | | |_| \__ \");
            Console.WriteLine(@" \___/|_|_|   \__\_/\___/\_|   |_| |_|\__, |___/");
            Console.WriteLine(@"                                       __/ |    ");
            Console.WriteLine(@"                                      |___/     ");
            Console.WriteLine(@"                                                ");
            Console.WriteLine(@"                                         ~b33f  ");
        }

        public static void GetHelp()
        {
            Console.WriteLine("\n ~~ Usage ~~ \n");
            Console.WriteLine(" -l (-Load)         Load Razer driver.");
            Console.WriteLine(" -u (-Unload)       Unload Razer driver.");
            Console.WriteLine(" -v (-VirtToPhys)   Translate VA to PA.\n");
        }
    }
}
