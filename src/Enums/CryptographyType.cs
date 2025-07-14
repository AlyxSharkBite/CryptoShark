using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Enums
{
    public enum CryptographyType
    {
        /// <summary>
        /// ECC - Public/Private Key Cryptography
        /// </summary>
        EllipticalCurveCryptography,

        /// <summary>
        /// RSA - Public/Private Key Cryptography
        /// </summary>
        RivestShamirAdlemanCryptography,

        /// <summary>
        /// Traditional Password Based Cryptography
        /// </summary>
        PasswordBasedCryptography
    }
}
