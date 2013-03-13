using System;
using System.Security.Cryptography;

namespace ASCrypt
{
    /// <summary>
    /// Available operation modes.
    /// </summary>
    public enum OperationMode
    {
        ECB = (Int32)CipherMode.ECB,
        CFB = (Int32)CipherMode.CFB,
        CTS = (Int32)CipherMode.CTS,
        OFB = (Int32)CipherMode.OFB,
        CBC = (Int32)CipherMode.CBC
    }

}
