using System;
using System.IO;
using System.Security.Cryptography;

namespace ASCrypt
{
    public class AES
    {
        /// <summary>
        /// Private error message constants of the class.
        /// </summary>
		private static readonly String ERROR_KEY = "Invalid key size. Key size needs to be either 128, 192 or 256 bits.\n";
		private static readonly String ERROR_BLOCK = "Invalid block size. Block size is fixed at 128 bits.\n";
        
        /// <summary>
        /// Encrypts bytes with the specified key and IV.
        /// </summary>
        public static Byte[] Encrypt(Byte[] key, Byte[] bytes, OperationMode mode, Byte[] iv)
        {
            Check(key, bytes);
            RijndaelManaged aes = new RijndaelManaged();
            if (iv != null) aes.IV = iv;
            aes.Mode = (CipherMode)mode;
            aes.Padding = PaddingMode.None;
            if (key.Length == 24) aes.KeySize = 192;
            else if (key.Length == 32) aes.KeySize = 256;
            else aes.KeySize = 128; // Defaults to 128
            aes.BlockSize = 128; aes.Key = key;
            ICryptoTransform ict = aes.CreateEncryptor();
            MemoryStream mStream = new MemoryStream();
            CryptoStream cStream = new CryptoStream(mStream, ict, CryptoStreamMode.Write);
            cStream.Write(bytes, 0, bytes.Length);
            cStream.FlushFinalBlock();
            mStream.Close(); cStream.Close();
            return mStream.ToArray();
        }

        /// <summary>
        /// Decrypts bytes with the specified key and IV.
        /// </summary>
        public static Byte[] Decrypt(Byte[] key, Byte[] bytes, OperationMode mode, Byte[] iv)
        {
            Check(key, bytes);
            RijndaelManaged aes = new RijndaelManaged();
            if (iv != null) aes.IV = iv;
            aes.Mode = (CipherMode)mode;
            aes.Padding = PaddingMode.None;
            if (key.Length == 24) aes.KeySize = 192;
            else if (key.Length == 32) aes.KeySize = 256;
            else aes.KeySize = 128; // Defaults to 128
            aes.BlockSize = 128; aes.Key = key;
            ICryptoTransform ict = aes.CreateDecryptor();
            MemoryStream mStream = new MemoryStream();
            CryptoStream cStream = new CryptoStream(mStream, ict, CryptoStreamMode.Write);
            cStream.Write(bytes, 0, bytes.Length);
            cStream.FlushFinalBlock();
            mStream.Close(); cStream.Close();
            return mStream.ToArray();
        }
        
        /// <summary>
        /// Checks the arguments and throws exceptions if needed.
        /// </summary>
        private static void Check(Byte[] k, Byte[] b)
		{
			Int32 kl = k.Length;
			if (kl != 16 && kl != 24 && kl != 32) throw new Exception(ERROR_KEY);
			if (b.Length % 16 != 0) throw new Exception(ERROR_BLOCK);
		}

    }

}
