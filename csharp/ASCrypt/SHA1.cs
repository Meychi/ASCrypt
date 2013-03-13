using System;
using System.Security.Cryptography;

namespace ASCrypt
{
    public class SHA1
    {
        /// <summary>
        /// Computes the SHA-1 checksum for the bytes.
        /// </summary>
        public static Byte[] Compute(Byte[] bytes)
        {
            SHA1Managed sha1 = new SHA1Managed();
            return sha1.ComputeHash(bytes);
        }

        /// <summary>
        /// Computes the HMAC-SHA-1 for the key and bytes.
        /// </summary>
        public static Byte[] ComputeHMAC(Byte[] key, Byte[] bytes)
        {
            HMACSHA1 hmac = new HMACSHA1(key);
            return hmac.ComputeHash(bytes);
        }

    }

}
