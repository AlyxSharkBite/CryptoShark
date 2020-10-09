using System;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CryptoShark.Dto
{
    ///<inheritdoc/>
    public class PBEncryptionResult : EncryptionResult
    {
        private readonly byte[] _hmac;
        private readonly int _itterations;
        private readonly byte[] _pbkdfSalt;       

        /// <summary>
        ///     SHA384 HMAC Hash of the Unencrypted Data        
        /// </summary>
        [JsonIgnore]
        public ReadOnlySpan<byte> Sha384Hmac => _hmac;

        /// <summary>
        ///     Number of itterations used in the
        ///     PBKDF2 Password Derivation 
        /// </summary>
        [JsonIgnore]
        public int Itterations => _itterations;

        /// <summary>
        ///     Salt used in the PBKDF2 Key Derivation
        /// </summary>
        [JsonIgnore]
        public ReadOnlySpan<byte> PbkdfSalt => _pbkdfSalt;

        internal PBEncryptionResult(ReadOnlySpan<byte> encryptedData, ReadOnlySpan<byte> gcmNonce, EncryptionAlgorithm encryptionAlgorithm, ReadOnlySpan<byte> sha3Hash, int itterations, ReadOnlySpan<byte> pbkdfSalt)
            : base(encryptedData, gcmNonce, encryptionAlgorithm)
        {
            this._hmac = sha3Hash.ToArray();
            this._itterations = itterations;
            this._pbkdfSalt = pbkdfSalt.ToArray();
        }

        ///<inheritdoc/>
        public override string ToJson()
        {
            var returnData = GetBaseJson();            

            returnData.Add(new JProperty("PbkdfSalt", this._pbkdfSalt));
            returnData.Add(new JProperty("itterations", this._itterations));

            returnData.Add(new JProperty("Sha3Hash",
                BitConverter.ToString(this._hmac)
                .Replace("-", String.Empty)
                .ToLower()));

            return JsonConvert.SerializeObject(returnData, Formatting.Indented);

        }
    }
}
