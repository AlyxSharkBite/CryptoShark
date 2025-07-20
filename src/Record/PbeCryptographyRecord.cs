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
    /// Result of a Password Bases Entryption Operation
    /// </summary>
    [MessagePackObject]
    public record PbeCryptographyRecord : ISemetricRecordMarker
    {
        /// <summary>
        /// Cryptography Type
        /// </summary>        
        public const CryptographyType CryptographyRecordType = CryptographyType.PasswordBasedCryptography;

        /// <summary>
        ///     HMAC Hash of the Unencrypted Data        
        /// </summary>
        [Required]
        [MessagePack.Key(0)]
        public byte[] Hash { get; init; }

        /// <summary>
        ///     Salt used in the PBKDF2 Key Derivation
        /// </summary>
        [Required]
        [MessagePack.Key(1)]
        public byte[] Salt { get; init; }

        /// <summary>
        ///     Number of iterations used in the
        ///     PBKDF2 Password Derivation 
        /// </summary>
        [Required]
        [MessagePack.Key(2)]
        public int Iterations { get; init; }

        /// <summary>
        ///     The Encrypted Data
        /// </summary>
        [Required]
        [MessagePack.Key(3)]
        public byte[] EncryptedData { get; init; }

        /// <summary>
        ///     GCM Nonce Token
        ///     used to encrypt the data
        /// </summary>
        [Required]
        [MessagePack.Key(4)]
        public byte[] Nonce { get; init; }

        /// <summary>
        ///     Encryption Algorithm Used
        /// </summary>
        [Required]
        [MessagePack.Key(5)]
        public EncryptionAlgorithm EncryptionAlgorithm { get; init; }

        /// <summary>
        ///     Hashing Algorithm Used
        /// </summary>
        [Required]
        [MessagePack.Key(6)]
        public HashAlgorithm HashAlgorithm { get; init; }
    }
}
