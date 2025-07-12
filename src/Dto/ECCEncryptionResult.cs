using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Serialization;
using CryptoShark.Enums;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Bson;
using Formatting = Newtonsoft.Json.Formatting;

namespace CryptoShark.Dto
{
    ///<inheritdoc/>
    public sealed class ECCEncryptionResult : IEncryptionResult
    {
        /// <summary>
        ///     ECC Public Key for Derivation and Signature Verification
        /// </summary>
        public byte[] ECCPublicKey { get; set; }

        /// <summary>
        ///     Signature of the Decrypted Data
        /// </summary>
        public byte[] ECCSignature { get; set; }

        ///<inheritdoc/>
        public byte[] EncryptedData { get; set; }
        
        ///<inheritdoc/>
        public byte[] GcmNonce { get; set; }
        
        ///<inheritdoc/>
        public EncryptionAlgorithm Algorithm { get; set; }

        ///<inheritdoc/>
        public ReadOnlySpan<byte> Serialize()
        {
            return SerializeBson().ToArray();
        }

        private ECCEncryptionResult()
        {
        }
        
        /// <summary>
        /// Public Constructor
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="gcmNonce"></param>
        /// <param name="eccPublicKey"></param>
        /// <param name="eccSignature"></param>
        /// <param name="algorithm"></param>
        public ECCEncryptionResult(byte[] encryptedData, byte[] gcmNonce, byte[] eccPublicKey, byte[] eccSignature,
            EncryptionAlgorithm algorithm)
        {
            EncryptedData = encryptedData;
            GcmNonce = gcmNonce;
            Algorithm = algorithm;
            ECCPublicKey = eccPublicKey;
            ECCSignature = eccSignature;
        }
        
        ///<inheritdoc/>
        public ReadOnlyMemory<byte> SerializeResult(SerializationMethod serializationMethod)
        {
            if (serializationMethod == SerializationMethod.BinarySerialization && EncryptedData.LongLength > Int32.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(EncryptedData));
            
            switch (serializationMethod)
            {
                case SerializationMethod.BinarySerialization:
                    return SerializeBinary();
                case SerializationMethod.BsonSerialization:
                    return SerializeBson();
                case SerializationMethod.JsonSerialization:
                    return SerializeJson();
                case SerializationMethod.XmlSerialization:
                    return SerializeXml();
                default:
                    throw new ArgumentOutOfRangeException(nameof(serializationMethod), serializationMethod, null);
            }
        }

        ///<inheritdoc/>
        public static IEncryptionResult Deserialize(ReadOnlyMemory<byte> data, 
            SerializationMethod serializationMethod = SerializationMethod.BsonSerialization)
        {
            switch (serializationMethod)
            {
                case SerializationMethod.BinarySerialization:
                    return DeSerializeBinary(data);
                case SerializationMethod.BsonSerialization:
                    return DeSerializeBson(data);
                case SerializationMethod.JsonSerialization:
                    return DeSerializeJson(data);
                case SerializationMethod.XmlSerialization:
                    return DeSerializeXml(data);
                default:
                    throw new ArgumentOutOfRangeException(nameof(serializationMethod), serializationMethod, null);
            }
        }

        private static ECCEncryptionResult DeSerializeBinary(ReadOnlyMemory<byte> data)
        {
            ECCEncryptionResult result = new ECCEncryptionResult();
            
            using MemoryStream inputStream = new MemoryStream(data.ToArray());
            using BinaryReader reader = new BinaryReader(inputStream);
            
            int len = reader.ReadInt32();
            result.ECCPublicKey = reader.ReadBytes(len);
            
            len = reader.ReadInt32();
            result.ECCSignature = reader.ReadBytes(len);
            
            len = reader.ReadInt32();
            if (len != -1)
                result.GcmNonce = reader.ReadBytes(len);
            
            result.Algorithm = (EncryptionAlgorithm)reader.ReadByte();
            
            len = reader.ReadInt32();
            result.EncryptedData = reader.ReadBytes(len);
            
            return result;
        }
        
        private static ECCEncryptionResult DeSerializeBson(ReadOnlyMemory<byte> data)
        {
            using MemoryStream inputStream = new MemoryStream(data.ToArray());
            using BinaryReader reader = new BinaryReader(inputStream);
            using BsonDataReader bsonDataReader = new BsonDataReader(reader);
            
            JsonSerializer serializer = new JsonSerializer();
            return serializer.Deserialize<ECCEncryptionResult>(bsonDataReader);
        }
        
        private static ECCEncryptionResult DeSerializeJson(ReadOnlyMemory<byte> data)
        {
            using MemoryStream inputStream = new MemoryStream(data.ToArray());
            using TextReader textReader = new StreamReader(inputStream);
            using JsonTextReader jsonReader = new JsonTextReader(textReader);
            
            JsonSerializer serializer = new JsonSerializer();
            
            return serializer.Deserialize<ECCEncryptionResult>(jsonReader);
        }
        
        private static ECCEncryptionResult DeSerializeXml(ReadOnlyMemory<byte> data)
        {
            XmlSerializer xmlSerializer = new XmlSerializer(typeof(ECCEncryptionResult));
            
            using MemoryStream inputStream = new MemoryStream(data.ToArray());
            using TextReader textReader = new StreamReader(inputStream);
            using XmlReader xmlReader = new XmlTextReader(textReader);
          
            return (ECCEncryptionResult)xmlSerializer.Deserialize(xmlReader);
        }
        
        private ReadOnlyMemory<byte> SerializeBinary()
        {
            using MemoryStream outputStream = new MemoryStream();
            using BinaryWriter writer = new BinaryWriter(outputStream);
            
            writer.Write(ECCPublicKey.Length);
            writer.Write(ECCPublicKey);
            
            writer.Write(ECCSignature.Length);
            writer.Write(ECCSignature);

            if (GcmNonce == null || GcmNonce.Length == 0)
            {
                writer.Write(-1);
            }
            else
            {
                writer.Write(GcmNonce.Length);
                writer.Write(GcmNonce);
            }
            
            writer.Write((byte)Algorithm);
            
            writer.Write(EncryptedData.Length);
            writer.Write(EncryptedData);
            
            writer.Flush();
            return outputStream.ToArray();
        }
        
        private ReadOnlyMemory<byte> SerializeBson()
        {
            using MemoryStream outputStream = new MemoryStream();
            using BinaryWriter writer = new BinaryWriter(outputStream);
            using BsonDataWriter bsonDataWriter = new BsonDataWriter(writer);
            
            JsonSerializer serializer = new JsonSerializer();
            serializer.Serialize(bsonDataWriter, this, typeof(ECCEncryptionResult));
            
            bsonDataWriter.Flush();
            writer.Flush();
            
            return outputStream.ToArray();
        }
        
        private ReadOnlyMemory<byte> SerializeJson()
        {
            using MemoryStream outputStream = new MemoryStream();
            using TextWriter writer = new StreamWriter(outputStream);
            using JsonTextWriter jsonTextWriter = new JsonTextWriter(writer);
            
            JsonSerializer serializer = new JsonSerializer();
            serializer.Serialize(jsonTextWriter, this, typeof(ECCEncryptionResult));
            
            jsonTextWriter.Flush();
            writer.Flush();
            
            return outputStream.ToArray();
        }
        
        private ReadOnlyMemory<byte> SerializeXml()
        {
            XmlSerializer xmlSerializer = new XmlSerializer(typeof(ECCEncryptionResult));
            using MemoryStream outputStream = new MemoryStream();
            using XmlTextWriter writer = new XmlTextWriter(outputStream, Encoding.UTF8);
            
            xmlSerializer.Serialize(writer, this);
            writer.Flush();
            
            return outputStream.ToArray();
        }
    }
}
