using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace FinchGen
{
    class Helper
    {
        // Template for DiscerningFinch
        public static string PayloadConfig = @"using System;

namespace DiscerningFinch
{{
    class Payload
    {{
        public static String sCheckSum = ""{0}"";
        public static String sPayloadArray = ""{1}"";
    }}
}}
";

        public static List<Byte[]> GzipCompressFileToArray(String FilePath)
        {
            // Generate output object
            List<Byte[]> lCompression = new List<byte[]>();

            if (!File.Exists(FilePath))
            {
                return lCompression;
            }

            // Read all file bytes
            byte[] bFile = File.ReadAllBytes(FilePath);

            // Compress
            MemoryStream CompStream = new MemoryStream();
            var zipStream = new GZipStream(CompStream, CompressionMode.Compress);
            zipStream.Write(bFile, 0, bFile.Length);
            zipStream.Close();

            // Generate checksum
            SHA256 sha256 = new SHA256CryptoServiceProvider();
            Byte[] bChecksum = sha256.ComputeHash(CompStream.ToArray());

            // Populate list object
            lCompression.Add(bChecksum);
            lCompression.Add(CompStream.ToArray());

            return lCompression;
        }

        public static String AESKeyToB64(Byte[] bInput, String sKey)
        {
            Byte[][] aSHAKeyMatt = ComputeSha256KeyMat(sKey);
            return AES256EncryptToString(bInput, aSHAKeyMatt[0], aSHAKeyMatt[1]);
        }

        public static Byte[][] ComputeSha256KeyMat(String sInput)
        {
            Byte[][] res = new Byte[2][];
            Encoding enc = Encoding.UTF8;

            SHA256 sha256 = new SHA256CryptoServiceProvider();
            byte[] hashKey = sha256.ComputeHash(enc.GetBytes(sInput));
            byte[] hashIV = sha256.ComputeHash(enc.GetBytes(sInput));
            Array.Resize(ref hashIV, 16);

            res[0] = hashKey;
            res[1] = hashIV;

            return res;
        }

        public static String AES256EncryptToString(Byte[] bInput, Byte[] bKey, Byte[] bIV)
        {
            if (bKey == null || bKey.Length <= 0)
            {
                return String.Empty;
            }
            if (bIV == null || bIV.Length <= 0)
            {
                return String.Empty;
            }

            byte[] encrypted;

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = bKey;
                aesAlg.IV = bIV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (BinaryWriter swEncrypt = new BinaryWriter(csEncrypt))
                        {
                            swEncrypt.Write(bInput);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return Convert.ToBase64String(encrypted);
        }
    }
}
