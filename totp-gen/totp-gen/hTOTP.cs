using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace totp_gen
{
    public class hTOTP
    {
        // Fluff
        //===================================================
        public static void printBanner()
        {
            Console.WriteLine(@"  _       _                          ");
            Console.WriteLine(@" | |_ ___| |_ _ __ ___ __ _ ___ ___  ");
            Console.WriteLine(@" |  _/ _ \  _| '_ \___/ _` / -_)   \ ");
            Console.WriteLine(@"  \__\___/\__| .__/   \__, \___|_||_|");
            Console.WriteLine(@"             |_|      |___/          " + "\n");
        }
        
        public static void getHelp()
        {
           Console.WriteLine("-=Flags=-\n");
           Console.WriteLine("-s/--seed   String, secret seed for the TOTP generator");
           Console.WriteLine("-c/--code   UInt32, TOTP code to validate");
           Console.WriteLine("\n-=Usage=-\n");
           Console.WriteLine("// Generate TOTP from seed");
           Console.WriteLine("totp_gen.exe -s HelloWorld\n");
           Console.WriteLine("// Validate TOTP code");
           Console.WriteLine("totp_gen.exe -s HelloWorld -c 1766951436");
        }
        
        // Structs
        //===================================================
        [StructLayout(LayoutKind.Sequential)]
        public struct TOTP
        {
            public UInt32 Seconds;
            public UInt32 Code;
        }
        
        // Functions
        //===================================================
        public static TOTP generateTOTP(String sSeed)
        {
            // Create return object
            TOTP oTOTP = new hTOTP.TOTP();
            
            // Get DatTime
            DateTime dtNow = DateTime.UtcNow;
            oTOTP.Seconds = (UInt32)(60 - dtNow.Second);

            // Subtract seconds from current time
            dtNow = dtNow.AddSeconds(-dtNow.Second);
            
            // Init HMAC with DateTime key & compute hash with seed value
            HMACSHA256 hmac = new HMACSHA256(Encoding.ASCII.GetBytes(dtNow.ToString(CultureInfo.InvariantCulture)));
            Byte[] bHash = hmac.ComputeHash(Encoding.ASCII.GetBytes(sSeed));
            
            // Get TOTP
            UInt32 iOffset = (UInt32)bHash[bHash.Length - 1] & 0xF;
            oTOTP.Code = (UInt32)((bHash[iOffset] & 0x7F) << 24 | (bHash[iOffset + 1] & 0xFF) << 16 | (bHash[iOffset + 2] & 0xFF) << 8 | (bHash[iOffset + 3] & 0xFF) % 1000000);
            
            // Return TOTP
            return oTOTP;
        }
        
        public static Boolean validateTOTP(String sSeed, UInt32 iCode)
        {
            // Get TOTP for seed
            TOTP oTOTP = generateTOTP(sSeed);
            
            // Check if code is valid
            return (oTOTP.Code == iCode);
        }
    }
}