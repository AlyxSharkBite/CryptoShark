using System;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Newtonsoft.Json.Linq;

namespace CryptoShark.Dto
{
    ///<inheritdoc/>
    public class RSAEncryptionResult : EncryptionResult
    {
        /// <summary>
        ///     RSA Public Key Used to Create Signature
        /// </summary>
        public byte[] RSAPublicKey { get; set; }    

        /// <summary>
        ///     RSA Signature of the Devrypted Data
        /// </summary>
        public byte[] RSASignature { get; set; }

        /// <summary>
        ///     RSA Encrypted Encryption Key
        /// </summary>
        public byte[] EncryptionKey { get; set; }

        ///<inheritdoc/>
        public override ReadOnlySpan<byte> Serialize()
        {
            using (MemoryStream outputStream = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(outputStream))
                using (BsonDataWriter bsonDataWriter = new BsonDataWriter(writer))
                {
                    JsonSerializer serializer = new JsonSerializer();
                    serializer.Serialize(bsonDataWriter, this, typeof(RSAEncryptionResult));
                }

                return outputStream.ToArray();
            }
        }

        /// <summary>
        ///     Deserializes a PBEncryptionResult from byte array
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static RSAEncryptionResult Deserialize(ReadOnlySpan<byte> data)
        {
            using (MemoryStream inputStream = new MemoryStream(data.ToArray()))
            {
                using (BinaryReader reader = new BinaryReader(inputStream))
                using (BsonDataReader bsonDataReader = new BsonDataReader(reader))
                {
                    JsonSerializer serializer = new JsonSerializer();
                    return serializer.Deserialize<RSAEncryptionResult>(bsonDataReader);
                }
            }
        }

    }
}
