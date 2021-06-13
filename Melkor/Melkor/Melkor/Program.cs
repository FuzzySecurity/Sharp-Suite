using System;
using System.IO;

namespace Melkor
{
    class Program
    {
        public static void runTest()
        {
            // Encrypt module
            //==============
            Console.WriteLine("[>] Reading assembly as Byte[]");
            Byte[] bMod = File.ReadAllBytes(@"C:\Users\b33f\tools\Dev\Melkor\Melkor\demoModule.exe");
            Console.WriteLine("[>] DPAPI CryptProtectData -> assembly[]");
            hMelkor.DPAPI_MODULE dpMod = hMelkor.dpapiEncryptModule(bMod, "Melkor", 0);
            if (dpMod.pMod != IntPtr.Zero)
            {
                Console.WriteLine("    |_ Success");
                Console.WriteLine("    |_ pCrypto : 0x" + String.Format("{0:X}", (dpMod.pMod).ToInt64()));
                Console.WriteLine("    |_ iSize   : " + dpMod.iModSize);
                bMod = null;
            } else
            {
                Console.WriteLine("\n[!] Failed to DPAPI encrypt module..");
                return;
            }

            Console.WriteLine("\n[?] Press enter to continue..");
            Console.ReadLine();

            // Create AppDomain & load module
            //==============
            Console.WriteLine("[>] DPAPI CryptUnprotectData -> assembly[] copy");
            hMelkor.DPAPI_MODULE oMod = hMelkor.dpapiDecryptModule(dpMod);
            if (oMod.iModSize != 0)
            {
                Console.WriteLine("    |_ Success");
            } else
            {
                Console.WriteLine("\n[!] Failed to DPAPI decrypt module..");
                return;
            }
            Console.WriteLine("[>] Create new AppDomain and invoke module through proxy..");
            AppDomain oAngband = hMelkor.loadAppDomainModule("dothething", "Angband", oMod.bMod);

            Console.WriteLine("\n[?] Press enter to continue..");
            Console.ReadLine();

            // Remove Appdomain and free CryptUnprotectData
            //==============
            Console.WriteLine("[>] Unloading AppDomain");
            hMelkor.unloadAppDomain(oAngband);
            Console.WriteLine("[>] Freeing CryptUnprotectData");
            hMelkor.freeMod(oMod);

            Console.WriteLine("\n[?] Press enter to exit..");
            Console.ReadLine();
        }

        static void Main(string[] args)
        {
            hMelkor.printBanner();
            runTest();
        }
    }
}
