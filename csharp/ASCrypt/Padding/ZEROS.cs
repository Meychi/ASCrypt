using System;

namespace ASCrypt.Padding
{
    public class ZEROS
    {
        /// <summary>
        /// Pads the bytes with zero byte padding scheme.
        /// </summary>
        public static Byte[] Pad(Byte[] bytes, Int32 size)
        {
            Byte[] c = (Byte[])bytes.Clone();
            while (c.Length % size != 0)
            {
                Array.Resize(ref c, c.Length + 1);
                c[c.Length - 1] = (Byte)0x00;
            }
            return c;
        }

        /// <summary>
        /// Unpads the bytes with zero byte padding scheme.
        /// </summary>
        public static Byte[] Unpad(Byte[] bytes)
        {
            Byte[] c = (Byte[])bytes.Clone();
            Byte s = (Byte)c[c.Length - 1];
            while (s == (Byte)0x00)
            {
                s = (Byte)c[c.Length - 2];
                Array.Resize(ref c, c.Length - 1);
            }
            return c;
        }

    }

}
