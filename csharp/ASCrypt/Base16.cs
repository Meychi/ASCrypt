using System;
using System.Security.Cryptography;

namespace ASCrypt
{
    public class Base16
    {
        /// <summary>
        /// Encodes bytes to a base16 string.
        /// </summary>
        public static String Encode(Byte[] bytes)
        {
            String hex = "";
            for (Int32 i = 0; i < bytes.Length; i++)
            {
                hex += bytes[i].ToString("x2");
            }
            return hex;
        }

        /// <summary>
        /// Decodes base16 string to bytes.
        /// </summary>
        public static Byte[] Decode(String base16)
        {
            Byte[] bytes = new Byte[base16.Length / 2];
            for (Int32 i = 0; i < base16.Length; i += 2)
            {
                Byte value = (Byte)Convert.ToInt32(base16.Substring(i, 2), 16);
                bytes.SetValue(value, i / 2);
            }
            return bytes;
        }

    }

}
