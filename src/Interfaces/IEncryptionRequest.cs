using CryptoShark.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Interfaces
{
    public interface IEncryptionRequest
    {
        /// <summary>
        /// Data To Encrypt
        /// </summary>
        byte[] ClearData { get; }

        /// <summary>
        /// Password
        /// </summary>
        SecureString Password { get; }

        /// <summary>
        ///     Encryption Algorithm To Use
        /// </summary>
        EncryptionAlgorithm EncryptionAlgorithm { get; }

        /// <summary>
        ///     Hash Algorithm To Use
        /// </summary>
        HashAlgorithm HashAlgorithm { get; }        
    }

    public interface IAsymetricEncryptionRequest : IEncryptionRequest
    {
        /// <summary>
        /// Public Key
        /// </summary>
        byte[] PublicKey { get; }


        /// <summary>
        /// Private Key
        /// </summary>
        byte[] PrivateKey { get; }

        /// <summary>
        /// Padding (RSA Only) 
        /// Default: OAEPWithSHA-256AndMGF1Padding
        /// </summary>
        string RsaPadding { get; }
    }
}
