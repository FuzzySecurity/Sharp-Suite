using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PickmansModel
{
	public class hCrypto
	{
		public static hPickman.AES_KEY_MAT ComputeSha256KeyMat(String sPass)
        {
            hPickman.AES_KEY_MAT oKeyMat = new hPickman.AES_KEY_MAT();
            Encoding enc = Encoding.UTF8;

            SHA256 sha256 = new SHA256CryptoServiceProvider();
            oKeyMat.bKey = sha256.ComputeHash(enc.GetBytes(sPass));
            // Hash sPass reverse
            oKeyMat.bIV = sha256.ComputeHash(enc.GetBytes(new String(sPass.Reverse().ToArray())));
            Array.Resize(ref oKeyMat.bIV, 16);

            return oKeyMat;
        }
		
        public static Byte[] toAES(String sPass, Byte[] bMessage)
        {
            // Key mat
            hPickman.AES_KEY_MAT oKeyMat = ComputeSha256KeyMat(sPass);

            // Encrypt
            using (AesManaged aes = new AesManaged())
            {
                aes.Key = oKeyMat.bKey;
                aes.IV = oKeyMat.bIV;
                
                ICryptoTransform enc = aes.CreateEncryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                    {
                        using (BinaryWriter sw = new BinaryWriter(cs))
                        {
                            sw.Write(bMessage);
                        }
                        return ms.ToArray();
                    }
                }
            }
        }
        
        public static Byte[] toAES(hPickman.ECDH_SHARED_KEY_MAT oKeyMat, Byte[] bMessage)
        {
	        using (AesManaged aes = new AesManaged())
	        {
		        aes.Key = oKeyMat.bDerivedKey;
		        aes.IV = oKeyMat.bIV;
                
		        ICryptoTransform enc = aes.CreateEncryptor(aes.Key, aes.IV);
		        using (MemoryStream ms = new MemoryStream())
		        {
			        using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
			        {
				        using (BinaryWriter sw = new BinaryWriter(cs))
				        {
					        sw.Write(bMessage);
				        }
				        return ms.ToArray();
			        }
		        }
	        }
        }
        
        public static Byte[] fromAES(String sPass, Byte[] bMessage)
        {
            // Key mat
            hPickman.AES_KEY_MAT oKeyMat = ComputeSha256KeyMat(sPass);

            // Encrypt
            using (Aes aes = Aes.Create())
            {
                aes.Key = oKeyMat.bKey;
                aes.IV = oKeyMat.bIV;
                
                ICryptoTransform dec = aes.CreateDecryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Write))
                    {
                        using (BinaryWriter sw = new BinaryWriter(cs))
                        {
                            sw.Write(bMessage);
                        }
                        return ms.ToArray();
                    }
                }
            }
        }
        
        public static Byte[] fromAES(hPickman.ECDH_SHARED_KEY_MAT oKeyMat, Byte[] bMessage)
        {
	        using (Aes aes = Aes.Create())
	        {
		        aes.Key = oKeyMat.bDerivedKey;
		        aes.IV = oKeyMat.bIV;
                
		        ICryptoTransform dec = aes.CreateDecryptor(aes.Key, aes.IV);
		        using (MemoryStream ms = new MemoryStream())
		        {
			        using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Write))
			        {
				        using (BinaryWriter sw = new BinaryWriter(cs))
				        {
					        sw.Write(bMessage);
				        }
				        return ms.ToArray();
			        }
		        }
	        }
        }

        public static ECDiffieHellmanCng initECDH()
        {
	        ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng();
	        ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
	        ecdh.HashAlgorithm = CngAlgorithm.Sha256;

	        return ecdh;
        }

        public static hPickman.ECDH_SHARED_KEY_MAT deriveECDH(ECDiffieHellmanCng oECDH, Byte[] bPKey)
        {
	        hPickman.ECDH_SHARED_KEY_MAT oShared = new hPickman.ECDH_SHARED_KEY_MAT();
	        CngKey remoteKey = CngKey.Import(bPKey, CngKeyBlobFormat.EccPublicBlob);

	        SHA256 sha256 = new SHA256CryptoServiceProvider();
	        oShared.bDerivedKey = oECDH.DeriveKeyMaterial(remoteKey);
	        oShared.bIV = sha256.ComputeHash(oShared.bDerivedKey);
	        Array.Resize(ref oShared.bIV, 16);
	        
	        return oShared;
        }
	}
}