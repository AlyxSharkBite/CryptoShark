using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Enums
{
    /// <summary>
    /// RSA Key Sizes
    /// </summary>
    public enum RsaKeySize
    {
        /// <summary>
        /// SECURITY STRENGTH | RECOMMENDED USE UNTIL
        /// ------------------+----------------------
        /// 80 AES            | Deprecated
       /// </summary>
        KeySize1024 = 1024,

        /// <summary>
        /// SECURITY STRENGTH | RECOMMENDED USE UNTIL
        /// ------------------+----------------------
        /// 112 AES           | 2030
        /// </summary>
        KeySize2048 = 2048,

        /// <summary>
        /// SECURITY STRENGTH | RECOMMENDED USE UNTIL
        /// ------------------+----------------------
        /// 128 AES           | Beyond 2030
        /// </summary>
        KeySize3072 = 3072,

        /// <summary>
        /// SECURITY STRENGTH | RECOMMENDED USE UNTIL
        /// ------------------+----------------------
        /// 156 AES           | Future-proofing
        /// </summary>
        KeySize4096 = 4096,

        /// <summary>
        /// SECURITY STRENGTH | RECOMMENDED USE UNTIL
        /// ------------------+----------------------
        /// 192 AES           | Future-proofing
        /// </summary>
        KeySize8192 = 7680,

        /// <summary>
        /// SECURITY STRENGTH | RECOMMENDED USE UNTIL
        /// ------------------+----------------------
        /// 256 AES           | Future-proofing
        /// </summary>
        KeySizw15360 = 15360
    }
}
