using System;
using System.Security.Cryptography;

namespace ASCrypt
{
    public class XXTEA
    {
        /// <summary>
        /// Private error message constants of the class.
        /// </summary>
		private static readonly String ERROR_KEY = "Invalid key size. Key size is fixed at 128 bits.\n";
        private static readonly String ERROR_BLOCK = "Invalid block size. Minimum block size is 64 bits and the block size needs to be multiple of 32 bits.\n";
        
        /// <summary>
        /// Encrypts bytes with the specified key.
        /// </summary>
        public static Byte[] Encrypt(Byte[] key, Byte[] bytes)
        {
            Check(key, bytes);
            UInt32[] k = UTILS.Pack(key);
            UInt32[] v = UTILS.Pack(bytes);
            if (v.Length <= 1) v[1] = 0; Int32 n = v.Length; Int32 q = 6 + 52 / n;
            UInt32 z = v[n - 1], m, y = v[0], d = 0x9E3779B9, s = 0, e;
			while (q-- > 0) 
			{
                s = unchecked(s + d);
				e = s >> 2 & 3;
				for (Int32 i = 0; i < n; i++)
				{
					y = v[(i + 1) % n];
					m = unchecked((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (s ^ y) + (k[i & 3 ^ e] ^ z));
                    z = v[i] = unchecked(v[i] + m);
				}
			}
            return UTILS.Unpack(v);
        }

        /// <summary>
        /// Decrypts bytes with the specified key.
        /// </summary>
        public static Byte[] Decrypt(Byte[] key, Byte[] bytes)
        {
            Check(key, bytes);
            UInt32[] k = UTILS.Pack(key);
            UInt32[] v = UTILS.Pack(bytes);
            Int32 n = v.Length, q = 6 + 52 / n;
            UInt32 z = v[n - 1], y = v[0], d = 0x9E3779B9, e;
            UInt32 m, s = unchecked((UInt32)(q * d));
			while (s != 0) 
			{
				e = s >> 2 & 3;
				for (Int32 i = n - 1; i >= 0; i--)
				{
					z = v[i > 0 ? i - 1 : n - 1];
					m = unchecked((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (s ^ y) + (k[i & 3 ^ e] ^ z));
					y = v[i] = unchecked(v[i] - m);
				}
				s = unchecked(s - d);
			}
            return UTILS.Unpack(v);
        }

        /// <summary>
        /// Checks the arguments and throws exceptions if needed.
        /// </summary>
        private static void Check(Byte[] k, Byte[] b)
		{
			if (k.Length != 16) throw new Exception(ERROR_KEY);
			if (b.Length < 8 || b.Length % 4 != 0) throw new Exception(ERROR_BLOCK);
		}

    }

}
