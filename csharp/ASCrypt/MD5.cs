using System;
using System.Security.Cryptography;

namespace ASCrypt
{
    public class MD5
    {
        /// <summary>
        /// Computes the MD5 checksum for the bytes.
        /// </summary>
        public static Byte[] Compute(Byte[] bytes)
        {
            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            return md5.ComputeHash(bytes);
        }

        /// <summary>
        /// Computes the HMAC-MD5 for the key and bytes.
        /// </summary>
        public static Byte[] ComputeHMAC(Byte[] key, Byte[] bytes)
        {
            HMACMD5 hmac = new HMACMD5(key);
            return hmac.ComputeHash(bytes);
        }

    }

}
