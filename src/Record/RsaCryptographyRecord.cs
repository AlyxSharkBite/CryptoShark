using CryptoShark.Enums;
using CryptoShark.Interfaces;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace CryptoShark.Record
{
    /// <summary>
    /// Result of a RSA Entryption Operation
    /// </summary>
    public record RsaCryptographyRecord : IAsemetricRecordMarker
    {
        /// <summary>
        /// Cryptography Type
        /// </summary>        
        public const CryptographyType CryptographyRecordType = CryptographyType.RivestShamirAdlemanCryptography;

        /// <summary>
        ///     RSA Public Key Used to Create Signature
        /// </summary>
        [Required]
        public byte[] PublicKey { get; init; }

        /// <summary>
        ///     RSA Signature of the Devrypted Data
        /// </summary>
        [Required]
        public byte[] Signature { get; init; }

        /// <summary>
        ///     RSA Encrypted Encryption Key
        /// </summary>
        [Required]
        public byte[] EncryptionKey { get; init; }

        /// <summary>
        ///     The Encrypted Data
        /// </summary>
        [Required]
        public byte[] EncryptedData { get; init; }

        /// <summary>
        ///     GCM Nonce Token
        ///     used to encrypt the data
        /// </summary>
        [Required]
        public byte[] Nonce { get; init; }

        /// <summary>
        ///     Encryption Algorithm Used
        /// </summary>
        [Required]
        public EncryptionAlgorithm EncryptionAlgorithm { get; init; }

        /// <summary>
        ///     Hashing Algorithm Used
        /// </summary>
        [Required]
        public HashAlgorithm HashAlgorithm { get; init; }

        /// <summary>
        /// Padding 
        /// Default: OAEPWithSHA-256AndMGF1Padding
        /// </summary>
        [Required]
        [DefaultValue("OAEPWithSHA-256AndMGF1Padding")]
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]        
        public string RsaPadding { get; init; }
    }
}
