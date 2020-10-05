using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CryptoShark.Dto
{
    public abstract class EncryptionResult
    {
        private readonly byte[] _encryptedData;
        private readonly byte[] _gcmNonce;
        private readonly EncryptionAlgorithm _encryptionAlgorithm;

        /// <summary>
        ///     The Encrypted Data
        /// </summary>
        [JsonIgnore]
        public ReadOnlySpan<byte> EncryptedData => _encryptedData;

        /// <summary>
        ///     GCM Nonce Token
        ///     used to encrypt the data
        /// </summary>
        [JsonIgnore]
        public ReadOnlySpan<byte> GcmNonce => _gcmNonce;

        /// <summary>
        ///     Encryption Algorithm Used
        /// </summary>
        [JsonIgnore]
        public EncryptionAlgorithm Algorithm => _encryptionAlgorithm;

        protected EncryptionResult(ReadOnlySpan<byte> encryptedData, ReadOnlySpan<byte> gcmNonce, EncryptionAlgorithm encryptionAlgorithm)
        {
            this._encryptedData = encryptedData.ToArray();
            this._gcmNonce = gcmNonce.ToArray();
            this._encryptionAlgorithm = encryptionAlgorithm;
        }

        /// <summary>
        ///     Returns a JSON Encoded String of the Object
        /// </summary>
        /// <returns></returns>
        public abstract string ToJson();

        protected virtual JObject GetBaseJson()
        {
            JObject returnData = new JObject();
            returnData.Add(new JProperty("EncryptedData", _encryptedData));
            returnData.Add(new JProperty("GcmNonce", _gcmNonce));
            returnData.Add(new JProperty("Algorithm", _encryptionAlgorithm.ToString()));

            return returnData;
        }

    }
}
