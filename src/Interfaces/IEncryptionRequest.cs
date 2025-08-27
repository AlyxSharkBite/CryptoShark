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
        ReadOnlyMemory<byte> ClearData { get; }

        /// <summary>
        /// Password
        /// </summary>
        SecureString Password { get; }

        /// <summary>
        ///     Encryption Algorithm To Use
        /// If null will default to ICryptoSharkConfiguration
        /// or TwoFish if that is not specified
        /// </summary>
        EncryptionAlgorithm? EncryptionAlgorithm { get; }

        /// <summary>
        ///     Hash Algorithm To Use
        /// If null will default to ICryptoSharkConfiguration
        /// or SHA-256 if that is not specified
        /// </summary>
        HashAlgorithm? HashAlgorithm { get; }

        /// <summary>
        /// Compress data before encryption
        /// If null will default to ICryptoSharkConfiguration
        /// or FALSE if that is not specified
        /// </summary>
        bool? CompressData { get; }
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
        /// Defaults to ICryptoSharkConfiguration
        /// or OAEPWithSHA-256AndMGF1Padding
        /// </summary>
        string RsaPadding { get; }
    }
}
