using System;
using System.Security.Cryptography;

namespace ASCrypt
{
    public class SHA256
    {
        /// <summary>
        /// Computes the SHA-256 checksum for the bytes.
        /// </summary>
        public static Byte[] Compute(Byte[] bytes)
        {
            SHA256Managed sha256 = new SHA256Managed();
            return sha256.ComputeHash(bytes);
        }

        /// <summary>
        /// Computes the HMAC-SHA-256 for the key and bytes.
        /// </summary>
        public static Byte[] ComputeHMAC(Byte[] key, Byte[] bytes)
        {
            HMACSHA256 hmac = new HMACSHA256(key);
            return hmac.ComputeHash(bytes);
        }

    }

}
