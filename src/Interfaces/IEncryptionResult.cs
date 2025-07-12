using System;
using CryptoShark.Enums;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CryptoShark.Dto
{
    /// <summary>
    ///     Encryption Results
    /// </summary>
    public interface IEncryptionResult
    {
        /// <summary>
        ///     The Encrypted Data
        /// </summary>
        byte[] EncryptedData { get; }

        /// <summary>
        ///     GCM Nonce Token
        ///     used to encrypt the data
        /// </summary>
        byte[] GcmNonce { get; }

        /// <summary>
        ///     Encryption Algorithm Used
        /// </summary>
        EncryptionAlgorithm Algorithm { get; }       

        /// <summary>
        ///     Serializes the Result to SerializationMethod:BsonSerialization
        /// </summary>
        /// <returns></returns>
        [Obsolete("Use SerializeResult instead", false)]
        ReadOnlySpan<byte> Serialize();
        
        /// <summary>
        /// Serializes the result object to the specified format
        /// </summary>
        /// <param name="serializationMethod">SerializationMethod</param>
        /// <returns></returns>
        ReadOnlyMemory<byte> SerializeResult(SerializationMethod serializationMethod);

        /// <summary>
        ///     Deserializes an EncryptionResult from byte array
        /// </summary>
        /// <param name="data">Serialized Result</param>
        /// <param name="serializationMethod">SerializationMethod</param>
        /// <returns></returns>
        static abstract IEncryptionResult Deserialize(ReadOnlyMemory<byte> data, SerializationMethod serializationMethod);
    }
}
