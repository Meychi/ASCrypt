using System;
using System.Security.Cryptography;

namespace ASCrypt
{
    public class GUID
    {
        /// <summary>
        /// Creates a new GUID.
        /// </summary>
        public static String Create()
        {
            return Guid.NewGuid().ToString();
        }

    }

}
