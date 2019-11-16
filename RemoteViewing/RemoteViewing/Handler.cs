using System;
using System.IO;
using System.Security.Cryptography;

namespace RemoteViewing
{
    class Handler
    {
        // Generate file path
        public static String GetOutputFilePath()
        {
            String sTempPath = Path.GetTempPath();
            return sTempPath + "_wasRDP36D7.tmp";
        }

        // Key material
        public static byte[] Key = { 0x00, 0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc, 0xdd, 0x44, 0x55, 0x66, 0x77 };
        public static byte[] IV = { 0x0a, 0x1b, 0x2c, 0x3d, 0xf9, 0xe8, 0xd7, 0xc6 };

        // RC2 encrypt data
        public static void EncryptTextToFile(String Data, String FileName, byte[] Key, byte[] IV)
        {
            FileStream fStream = File.Open(FileName, FileMode.OpenOrCreate);
            RC2 RC2alg = RC2.Create();
            CryptoStream cStream = new CryptoStream(fStream, RC2alg.CreateEncryptor(Key, IV), CryptoStreamMode.Write);
            StreamWriter sWriter = new StreamWriter(cStream);
            sWriter.WriteLine(Data);
            sWriter.Close();
            cStream.Close();
            fStream.Close();
        }
    }
}
