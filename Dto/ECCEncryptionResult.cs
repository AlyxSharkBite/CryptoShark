using System;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Bson;

namespace CryptoShark.Dto
{
    ///<inheritdoc/>
    public class ECCEncryptionResult : EncryptionResult
    {
        /// <summary>
        ///     ECC Public Key for Derivation and Signature Verification
        /// </summary>
        public byte[] ECCPublicKey { get;set; }

        /// <summary>
        ///     Signature of the Decrypted Data
        /// </summary>
        public byte[] ECCSignature { get; set; }

        ///<inheritdoc/>
        public override ReadOnlySpan<byte> Serialize()
        {
            using(MemoryStream outputStream = new MemoryStream())
            {
                using(BinaryWriter writer = new BinaryWriter(outputStream)) 
                using (BsonDataWriter bsonDataWriter = new BsonDataWriter(writer))
                {
                    JsonSerializer serializer = new JsonSerializer();
                    serializer.Serialize(bsonDataWriter, this, typeof(ECCEncryptionResult));
                }

                return outputStream.ToArray();
            }
        }

        /// <summary>
        ///     Deserializes a ECCEncryptionResult from byte array
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static ECCEncryptionResult Deserialize(ReadOnlySpan<byte> data)
        {
            using(MemoryStream inputStream = new MemoryStream(data.ToArray()))
            {
                using(BinaryReader reader = new BinaryReader(inputStream))  
                using(BsonDataReader bsonDataReader = new BsonDataReader(reader))
                {
                    JsonSerializer serializer = new JsonSerializer();
                    return serializer.Deserialize<ECCEncryptionResult>(bsonDataReader);
                }
            }
        }
    }
}
