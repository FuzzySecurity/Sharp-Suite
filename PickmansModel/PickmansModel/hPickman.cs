using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;

namespace PickmansModel
{
    public class hPickman
    {
        // Data Model
        //========================
        [StructLayout(LayoutKind.Sequential)]
        public struct AES_KEY_MAT
        {
            public Byte[] bKey;
            public Byte[] bIV;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct ECDH_SHARED_KEY_MAT
        {
	        public Byte[] bDerivedKey;
	        public Byte[] bIV;
        }
        
        // Helpers
        //========================

        public static Byte[] StringToUTF32(String sInput)
        {
            return Encoding.UTF32.GetBytes(sInput);
        }
        
        public static String UTF32ToString(Byte[] bInput)
        {
            return Encoding.UTF32.GetString(bInput);
        }

        public static Byte[] ReadPipeMessage(PipeStream oPipe)
        {
	        Byte[] bBuff = new Byte[1024];
	        using (MemoryStream ms = new MemoryStream())
	        {
		        do
		        {
			        Int32 iFetchedBytes = oPipe.Read(bBuff, 0, bBuff.Length);
			        ms.Write(bBuff, 0, iFetchedBytes);
		        } while (!oPipe.IsMessageComplete);
		        return ms.ToArray();
	        }
        }
        
        // https://www.codeproject.com/Articles/36747/Quick-and-Dirty-HexDump-of-a-Byte-Array
        public static string HexDump(byte[] bytes, int bytesPerLine = 16)
        {
            if (bytes == null) return "<null>";
            int bytesLength = bytes.Length;

            char[] HexChars = "0123456789ABCDEF".ToCharArray();

            int firstHexColumn =
                  8                   // 8 characters for the address
                + 3;                  // 3 spaces

            int firstCharColumn = firstHexColumn
                + bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
                + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
                + 2;                  // 2 spaces 

            int lineLength = firstCharColumn
                + bytesPerLine           // - characters to show the ascii value
                + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

            char[] line = (new String(' ', lineLength - Environment.NewLine.Length) + Environment.NewLine).ToCharArray();
            int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
            StringBuilder result = new StringBuilder(expectedLines * lineLength);

            for (int i = 0; i < bytesLength; i += bytesPerLine)
            {
                line[0] = HexChars[(i >> 28) & 0xF];
                line[1] = HexChars[(i >> 24) & 0xF];
                line[2] = HexChars[(i >> 20) & 0xF];
                line[3] = HexChars[(i >> 16) & 0xF];
                line[4] = HexChars[(i >> 12) & 0xF];
                line[5] = HexChars[(i >> 8) & 0xF];
                line[6] = HexChars[(i >> 4) & 0xF];
                line[7] = HexChars[(i >> 0) & 0xF];

                int hexColumn = firstHexColumn;
                int charColumn = firstCharColumn;

                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= bytesLength)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        byte b = bytes[i + j];
                        line[hexColumn] = HexChars[(b >> 4) & 0xF];
                        line[hexColumn + 1] = HexChars[b & 0xF];
                        line[charColumn] = (b < 32 ? '·' : (char)b);
                    }
                    hexColumn += 3;
                    charColumn++;
                }
                result.Append(line);
            }
            return result.ToString();
        }
    }
}