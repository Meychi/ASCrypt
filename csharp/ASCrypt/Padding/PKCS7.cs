using System;

namespace ASCrypt.Padding
{
    public class PKCS7
    {
        /// <summary>
        /// Private error message constants of the class.
        /// </summary>
        private static readonly String ERROR_VALUE = "Invalid padding value. Got {0}, expected {1}.";
        
        /// <summary>
        /// Pads the bytes with PKCS#7 padding scheme.
        /// </summary>
        public static Byte[] Pad(Byte[] bytes, Int32 size)
        {
            Byte[] c = (Byte[])bytes.Clone();
            Int32 s = size - c.Length % size;
            for (Int32 i = 0; i < s; i++)
            {
                Array.Resize(ref c, c.Length + 1);
                c[c.Length - 1] = (Byte)s;
            }
            return c;
        }

        /// <summary>
        /// Unpads the bytes with PKCS#7 padding scheme.
        /// </summary>
        public static Byte[] Unpad(Byte[] bytes)
        {
            Byte[] c = (Byte[])bytes.Clone();
            Byte s = (Byte)c[c.Length - 1];
            for (Int32 i = s; i > 0; i--)
			{
				Int32 v = c[c.Length - 1];
                Array.Resize(ref c, c.Length - 1);
				if (s != v) 
				{
                    String msg = String.Format(ERROR_VALUE, v, s);
                    throw new Exception(msg);
				}
			}
            return c;
        }

    }

}
