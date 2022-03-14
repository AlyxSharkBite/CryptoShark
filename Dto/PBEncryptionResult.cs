using System;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Newtonsoft.Json.Linq;

namespace CryptoShark.Dto
{
    ///<inheritdoc/>
    public class PBEncryptionResult : EncryptionResult
    {
        /// <summary>
        ///     SHA384 HMAC Hash of the Unencrypted Data        
        /// </summary>
        public byte[] Sha384Hmac { get; set; }

        /// <summary>
        ///     Salt used in the PBKDF2 Key Derivation
        /// </summary>
        public byte[] PbkdfSalt { get; set; }

        /// <summary>
        ///     Number of itterations used in the
        ///     PBKDF2 Password Derivation 
        /// </summary>
        public int Itterations { get; set; }

        ///<inheritdoc/>
        public override ReadOnlySpan<byte> Serialize()
        {
            using (MemoryStream outputStream = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(outputStream))
                using (BsonDataWriter bsonDataWriter = new BsonDataWriter(writer))
                {
                    JsonSerializer serializer = new JsonSerializer();
                    serializer.Serialize(bsonDataWriter, this, typeof(PBEncryptionResult));
                }

                return outputStream.ToArray();
            }
        }

        /// <summary>
        ///     Deserializes a PBEncryptionResult from byte array
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static PBEncryptionResult Deserialize(ReadOnlySpan<byte> data)
        {
            using (MemoryStream inputStream = new MemoryStream(data.ToArray()))
            {
                using (BinaryReader reader = new BinaryReader(inputStream))
                using (BsonDataReader bsonDataReader = new BsonDataReader(reader))
                {
                    JsonSerializer serializer = new JsonSerializer();
                    return serializer.Deserialize<PBEncryptionResult>(bsonDataReader);
                }
            }
        }
    }
}
