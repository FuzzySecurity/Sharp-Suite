using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Melkor
{
    class hMelkor
    {
        // API
        //======================
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtFreeVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            AllocationType FreeType);

        [DllImport("ntdll.dll")]
        public static extern void RtlZeroMemory(
            IntPtr Destination,
            int length);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(
            IntPtr hMem);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto)]
        public static extern bool CryptProtectData(
            ref DATA_BLOB pPlainText,
            string szDescription,
            ref DATA_BLOB pEntropy,
            IntPtr pReserved,
            IntPtr pPrompt,
            int dwFlags,
            ref DATA_BLOB pCipherText);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto)]
        public static extern bool CryptUnprotectData(
            ref DATA_BLOB pCipherText,
            ref string pszDescription,
            ref DATA_BLOB pEntropy,
            IntPtr pReserved,
            IntPtr pPrompt,
            int dwFlags,
            ref DATA_BLOB pPlainText);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CRYPTPROTECT_PROMPTSTRUCT
        {
            public int cbSize;
            public int dwPromptFlags;
            public IntPtr hwndApp;
            public string szPrompt;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct DPAPI_MODULE
        {
            public String sModName;
            public int iModVersion;
            public int iModSize;
            public IntPtr pMod;
            public Byte[] bMod;
        }

        [Flags]
        public enum AllocationType : uint
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            ResetUndo = 0x1000000,
            LargePages = 0x20000000
        }

        // Globals
        //======================
        public static Byte[] bEntropy = { 0x90, 0x91, 0x92, 0x93 }; // Add entropy to the crypto
        public static int CRYPTPROTECT_LOCAL_MACHINE = 0x4;
        public static Object CryptLock = new Object();

        public static void printBanner()
        {
            Console.WriteLine(@"   _____         .__   __                ");
            Console.WriteLine(@"  /     \   ____ |  | |  | _____________ ");
            Console.WriteLine(@" /  \ /  \_/ __ \|  | |  |/ /  _ \_  __ \");
            Console.WriteLine(@"/    Y    \  ___/|  |_|    <  <_> )  | \/");
            Console.WriteLine(@"\____|__  /\___  >____/__|_ \____/|__|   ");
            Console.WriteLine(@"        \/     \/          \/            " + "\n");
        }

        // Domain Proxy
        //======================
        public class ShadowRunnerProxy : MarshalByRefObject
        {
            public void LoadAssembly(byte[] byteArr, String sMethod)
            {
                Assembly a = Assembly.Load(byteArr);
                getAssemblies();
                Console.WriteLine("[+] Calling demoModule --> " + sMethod);
                foreach (var type in a.GetTypes())
                {
                    foreach (MethodInfo method in type.GetMethods())
                    {
                        if ((method.Name.ToLower()).Equals(sMethod.ToLower()))
                        {
                            object instance = Activator.CreateInstance(type);
                            method.Invoke(instance, new object[] { });
                            return;
                        }
                    }
                }
            }

            public void getAssemblies()
            {
                var domain = AppDomain.CurrentDomain;
                Console.WriteLine("[>] Executing in AppDomain -> " + domain.FriendlyName);
                Console.WriteLine("[+] " + domain.FriendlyName + " Loaded Modules");
                foreach (Assembly a in domain.GetAssemblies())
                {
                    Console.WriteLine("    |_ " + a.FullName);
                }
            }
        }

        // Helpers
        //======================
        public void getAssemblies()
        {
            var domain = AppDomain.CurrentDomain;
            Console.WriteLine("[>] Executing in AppDomain -> " + domain.FriendlyName);
            Console.WriteLine("[+] " + domain.FriendlyName + " Loaded Modules");
            foreach (Assembly a in domain.GetAssemblies())
            {
                Console.WriteLine("    |_ " + a.FullName);
            }
        }

        public static AppDomain loadAppDomainModule(String sMethod, String sAppDomain, Byte[] bMod)
        {
            AppDomain oDomain = AppDomain.CreateDomain(sAppDomain, null, null, null, false);
            ShadowRunnerProxy pluginProxy = (ShadowRunnerProxy)oDomain.CreateInstanceAndUnwrap(typeof(ShadowRunnerProxy).Assembly.FullName, typeof(ShadowRunnerProxy).FullName);
            pluginProxy.LoadAssembly(bMod, sMethod);
            return oDomain;
        }

        public static void unloadAppDomain(AppDomain oDomain)
        {
            AppDomain.Unload(oDomain);
        }

        public static DATA_BLOB makeBlob(Byte[] bData)
        {
            DATA_BLOB oBlob = new DATA_BLOB();

            oBlob.pbData = Marshal.AllocHGlobal(bData.Length);
            oBlob.cbData = bData.Length;
            RtlZeroMemory(oBlob.pbData, bData.Length);
            Marshal.Copy(bData, 0, oBlob.pbData, bData.Length);

            return oBlob;
        }

        public static void freeMod(DPAPI_MODULE oMod)
        {
            //IntPtr piLen = (IntPtr)oMod.iModSize;
            //NtFreeVirtualMemory((IntPtr)(-1), ref oMod.pMod, ref piLen, AllocationType.Release);
            LocalFree(oMod.pMod);
        }

        public static DPAPI_MODULE dpapiEncryptModule(Byte[] bMod, String sModName, Int32 iModVersion = 0)
        {
            DPAPI_MODULE dpMod = new DPAPI_MODULE();

            DATA_BLOB oPlainText = makeBlob(bMod);
            DATA_BLOB oCipherText = new DATA_BLOB();
            DATA_BLOB oEntropy = makeBlob(bEntropy);

            Boolean bStatus = CryptProtectData(ref oPlainText, sModName, ref oEntropy, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_LOCAL_MACHINE, ref oCipherText);
            if (bStatus)
            {
                dpMod.sModName = sModName;
                dpMod.iModVersion = iModVersion;
                dpMod.iModSize = oCipherText.cbData;
                dpMod.pMod = oCipherText.pbData;
            }

            return dpMod;
        }

        public static DPAPI_MODULE dpapiDecryptModule(DPAPI_MODULE oEncMod)
        {
            DPAPI_MODULE oMod = new DPAPI_MODULE();

            Byte[] bEncrypted = new Byte[oEncMod.iModSize];
            Marshal.Copy(oEncMod.pMod, bEncrypted, 0, oEncMod.iModSize);

            DATA_BLOB oPlainText = new DATA_BLOB();
            DATA_BLOB oCipherText = makeBlob(bEncrypted);
            DATA_BLOB oEntropy = makeBlob(bEntropy);

            String sDescription = String.Empty;
            Boolean bStatus = CryptUnprotectData(ref oCipherText, ref sDescription, ref oEntropy, IntPtr.Zero, IntPtr.Zero, 0, ref oPlainText);
            if (bStatus)
            {
                oMod.pMod = oPlainText.pbData;
                oMod.bMod = new Byte[oPlainText.cbData];
                Marshal.Copy(oPlainText.pbData, oMod.bMod, 0, oPlainText.cbData);
                oMod.iModSize = oPlainText.cbData;
                oMod.iModVersion = oEncMod.iModVersion;
            }

            return oMod;
        }
    }
}
