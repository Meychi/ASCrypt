using System;
using System.Security.Cryptography;

namespace ASCrypt
{
    public class Base64
    {
        /// <summary>
        /// Encodes bytes to a base64 string.
        /// </summary>
        public static String Encode(Byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// Decodes base64 string to bytes.
        /// </summary>
        public static Byte[] Decode(String base64)
        {
            return Convert.FromBase64String(base64);
        }

    }

}
