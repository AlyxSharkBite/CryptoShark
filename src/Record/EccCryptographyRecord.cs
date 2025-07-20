using CryptoShark.Enums;
using CryptoShark.Interfaces;
using MessagePack;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Record
{
    /// <summary>
    /// Result of an ECC Entryption Operation
    /// </summary>
    [MessagePackObject]
    public record EccCryptographyRecord : IAsemetricRecordMarker
    {
        /// <summary>
        /// Cryptography Type
        /// </summary>        
        public const CryptographyType CryptographyRecordType = CryptographyType.EllipticalCurveCryptography;

        /// <summary>
        ///     ECC Public Key for Derivation and Signature Verification
        /// </summary>
        [Required]
        [MessagePack.Key(0)]
        public byte[] PublicKey { get; init; }

        /// <summary>
        ///     Signature of the Decrypted Data
        /// </summary>
        [Required]
        [MessagePack.Key(1)]
        public byte[] Signature { get; init; }

        /// <summary>
        ///     The Encrypted Data
        /// </summary>
        [Required]
        [MessagePack.Key(2)]
        public byte[] EncryptedData { get; init; }

        /// <summary>
        ///     GCM Nonce Token
        ///     used to encrypt the data
        /// </summary>
        [Required]
        [MessagePack.Key(3)]
        public byte[] Nonce { get; init; }

        /// <summary>
        ///     Encryption Algorithm Used
        /// </summary>
        [Required]
        [MessagePack.Key(4)]
        public EncryptionAlgorithm EncryptionAlgorithm { get; init; }

        /// <summary>
        ///     Hashing Algorithm Used
        /// </summary>
        [Required]
        [MessagePack.Key(5)]
        public HashAlgorithm HashAlgorithm { get; init; }
    }
}
