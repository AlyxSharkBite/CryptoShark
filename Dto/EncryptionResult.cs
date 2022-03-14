using System;
using CryptoShark.Enums;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CryptoShark.Dto
{
    /// <summary>
    ///     Encryption Results
    /// </summary>
    public abstract class EncryptionResult
    {
        /// <summary>
        ///     The Encrypted Data
        /// </summary>
        public byte[] EncryptedData { get; set; }

        /// <summary>
        ///     GCM Nonce Token
        ///     used to encrypt the data
        /// </summary>
        public byte[] GcmNonce { get; set; }

        /// <summary>
        ///     Encryption Algorithm Used
        /// </summary>
        public EncryptionAlgorithm Algorithm { get; set; }       

        /// <summary>
        ///     Serializes the Result
        /// </summary>
        /// <returns></returns>
        public abstract ReadOnlySpan<byte> Serialize();
    }
}
