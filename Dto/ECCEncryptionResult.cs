using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CryptoShark.Dto
{
    public class ECCEncryptionResult : EncryptionResult
    {
        private readonly byte[] _eccPublicKey;
        private readonly byte[] _eccSignature;

        /// <summary>
        ///     ECC Public Key for Derivation and Signature Verification
        /// </summary>
        [JsonIgnore]
        public ReadOnlySpan<byte> ECCPublicKey => _eccPublicKey;

        /// <summary>
        ///     Signature of the Decrypted Data
        /// </summary>
        [JsonIgnore]
        public ReadOnlySpan<byte> ECCSignature => _eccSignature;

        internal ECCEncryptionResult(ReadOnlySpan<byte> encryptedData,
            ReadOnlySpan<byte> gcmNonce,
            EncryptionAlgorithm encryptionAlgorithm,
            ReadOnlySpan<byte> eccPublicKey,
            ReadOnlySpan<byte> eccSignature)
            : base(encryptedData, gcmNonce, encryptionAlgorithm)
        {
            _eccPublicKey = eccPublicKey.ToArray();
            _eccSignature = eccSignature.ToArray();
        }

        ///<inheritdoc/>
        public override string ToJson()
        {
            var returnData = GetBaseJson();

            returnData.Add(new JProperty("ECCPublicKey", this._eccPublicKey));            

            returnData.Add(new JProperty("ECCSignature",
                BitConverter.ToString(this._eccSignature)
                .Replace("-", String.Empty)
                .ToLower()));

            return JsonConvert.SerializeObject(returnData, Formatting.Indented);
        }
    }
}
