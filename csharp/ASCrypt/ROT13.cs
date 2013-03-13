using System;
using System.Security.Cryptography;

namespace ASCrypt
{
    public class ROT13
    {
        /// <summary>
        /// Characters used in the ROT13 calculation.
        /// </summary>
        private static readonly String chrs = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMabcdefghijklmnopqrstuvwxyzabcdefghijklm";

        /// <summary>
        /// Encodes bytes with ROT13 algorithm.
        /// </summary>
        public static Byte[] Encode(Byte[] bytes)
        {
            return Rot13(bytes);
        }

        /// <summary>
        /// Decodes bytes with ROT13 algorithm.
        /// </summary>
        public static Byte[] Decode(Byte[] bytes)
        {
            return Rot13(bytes);
        }

        /// <summary>
        /// The actual Rot13 XOR operation.
        /// </summary>
        private static Byte[] Rot13(Byte[] bytes)
        {
			Byte[] b = new Byte[bytes.Length];
            for (Int32 i = 0; i < bytes.Length; i++)
			{
                Int32 p = chrs.IndexOf((Char)bytes[i]);
                if (p > -1) b[i] = (Byte)chrs.ToCharArray(p + 13, 1)[0];
				else b[i] = bytes[i];
			}
			return b;
        }

    }

}
