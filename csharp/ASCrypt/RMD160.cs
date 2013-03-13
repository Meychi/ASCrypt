using System;
using System.Security.Cryptography;

namespace ASCrypt
{
    public class RMD160
    {
        /// <summary>
        /// Computes the RIPEMD-160 checksum for the bytes.
        /// </summary>
        public static Byte[] Compute(Byte[] bytes)
        {
            RIPEMD160Managed rmd160 = new RIPEMD160Managed();
            return rmd160.ComputeHash(bytes);
        }

        /// <summary>
        /// Computes the HMAC-RIPEMD-160 for the key and bytes.
        /// </summary>
        public static Byte[] ComputeHMAC(Byte[] key, Byte[] bytes)
        {
            HMACRIPEMD160 hmac = new HMACRIPEMD160(key);
            return hmac.ComputeHash(bytes);
        }

    }

}
