using System;

namespace ASCrypt
{
    class UTILS
    {
        /// <summary>
        /// Packs bytes to a 32-bit words.
        /// </summary>
        public static UInt32[] Pack(Byte[] data)
        {
            Int32 n = (((data.Length & 3) == 0) ? (data.Length >> 2) : ((data.Length >> 2) + 1));
            UInt32[] result = new UInt32[n];
            for (Int32 i = 0; i < data.Length; i++)
            {
                result[i >> 2] |= (UInt32)data[i] << ((i & 3) << 3);
            }
            return result;
        }

        /// <summary>
        /// Unpacks 32-bit words to bytes.
        /// </summary>
        public static Byte[] Unpack(UInt32[] data)
        {
            Int32 n = data.Length << 2;
            Byte[] result = new Byte[n];
            for (Int32 i = 0; i < n; i++)
            {
                result[i] = (Byte)(data[i >> 2] >> ((i & 3) << 3));
            }
            return result;
        }

    }

}
