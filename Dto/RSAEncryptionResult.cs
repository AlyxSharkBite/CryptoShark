using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CryptoShark.Dto
{
    ///<inheritdoc/>
    public class RSAEncryptionResult : EncryptionResult
    {
        private readonly byte[] _rsaPublicKey;
        private readonly byte[] _rsaSignature;
        private readonly byte[] _rsaEncryptedKey;

        /// <summary>
        ///     RSA Public Key Used to Create Signature
        /// </summary>
        [JsonIgnore]
        public ReadOnlySpan<byte> RSAPublicKey => _rsaPublicKey;

        /// <summary>
        ///     RSA Signature of the Devrypted Data
        /// </summary>
        [JsonIgnore]
        public ReadOnlySpan<byte> RSASignature => _rsaSignature;

        /// <summary>
        ///     RSA Encrypted Encryption Key
        /// </summary>
        [JsonIgnore]
        public ReadOnlySpan<byte> EncryptionKey => _rsaEncryptedKey;

       
        internal RSAEncryptionResult(ReadOnlySpan<byte> encryptedData,
            ReadOnlySpan<byte> gcmNonce,
            EncryptionAlgorithm encryptionAlgorithm,
            ReadOnlySpan<byte> rsaPublicKey,
            ReadOnlySpan<byte> rsaSignature,
            ReadOnlySpan<byte> rsaEncryptedKey)
            : base(encryptedData, gcmNonce, encryptionAlgorithm)
        {
            this._rsaPublicKey = rsaPublicKey.ToArray();
            this._rsaSignature = rsaSignature.ToArray();
            this._rsaEncryptedKey = rsaEncryptedKey.ToArray();
        }

        ///<inheritdoc/>
        public override string ToJson()
        {
            var returnData = GetBaseJson();
            
            returnData.Add(new JProperty("RSAPublicKey", this._rsaPublicKey));            
            returnData.Add(new JProperty("EncryptionKey", this._rsaEncryptedKey));

            returnData.Add(new JProperty("RSASignature",
                BitConverter.ToString(this._rsaSignature)
                .Replace("-", String.Empty)
                .ToLower()));

            return JsonConvert.SerializeObject(returnData, Formatting.Indented);

        }
    }
}
