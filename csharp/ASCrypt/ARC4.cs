using System;
using System.Security.Cryptography;

namespace ASCrypt
{
    public class ARC4
    {
        /// <summary>
        /// Private error message constants of the class.
        /// </summary>
        private static readonly String ERROR_KEY = "Invalid key size. Key size needs to be 40 - 128 bits.\n";
        
        /// <summary>
        /// Private static properties of the class.
        /// </summary>
        private static Int32[] sbox = new Int32[256];
        private static Int32[] mkey = new Int32[256];
        
        /// <summary>
        /// Encrypts bytes with the specified key.
        /// </summary>
        public static Byte[] Encrypt(Byte[] key, Byte[] bytes, Boolean init)
        {
            Check(key);
            return Arc4(key, bytes, init);
        }
        public static Byte[] Encrypt(Byte[] key, Byte[] bytes)
        {
            return Encrypt(key, bytes, true);
        }
        
        /// <summary>
        /// Decrypts bytes with the specified key.
        /// </summary>
        public static Byte[] Decrypt(Byte[] key, Byte[] bytes, Boolean init)
        {
            Check(key);
            return Arc4(key, bytes, init);
        }
        public static Byte[] Decrypt(Byte[] key, Byte[] bytes)
        {
            return Decrypt(key, bytes, true);
        }

        /// <summary>
        /// Core cipher method.
        /// </summary>
        private static Byte[] Arc4(Byte[] key, Byte[] bytes, Boolean init)
        {
            if (init) Initialize(key);
            Byte[] b = new Byte[bytes.Length];
			Int32 k; Int32 t; Int32 x; Int32 l = 0; Int32 j = 0;
			for (Int32 i = 0; i < bytes.Length; i++)
			{
				l = (l + 1) % 256;
				j = (j + sbox[l]) % 256;
                t = sbox[l];
                sbox[l] = sbox[j];
				sbox[j] = t;
				x = (sbox[l] + sbox[j]) % 256;
				k = sbox[x];
                b[i] = ((Byte)(bytes[i] ^ k));
			}
			return b;
        }

        /// <summary>
        /// Initializes the algorithm.
        /// </summary>
        private static void Initialize(Byte[] k)
		{
			Int32 l = k.Length;
			Int32 t; Int32 c = 0;
			for (Int32 i = 0; i <= 255; i++)
			{
				mkey[i] = (Int32)k[(i % l)];
				sbox[i] = i;
			}
			for (Int32 j = 0; j <= 255; j++)
			{
				c = (c + sbox[j] + mkey[j]) % 256;
				t = sbox[j]; sbox[j] = sbox[c];
                sbox[c] = t;
			}
		}

        /// <summary>
        /// Checks the arguments and throws exceptions if needed.
        /// </summary>
        private static void Check(Byte[] k)
		{
			Int32 kl = k.Length;
			if (kl < 5 || kl > 16) throw new Exception(ERROR_KEY);
		}

    }

}
