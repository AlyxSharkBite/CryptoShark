using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Serialization;
using CryptoShark.Enums;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Newtonsoft.Json.Linq;

namespace CryptoShark.Dto
{
    ///<inheritdoc/>
    public class RSAEncryptionResult : IEncryptionResult
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
        public byte[] EncryptedData { get; set; }
        
        ///<inheritdoc/>
        public byte[] GcmNonce { get; set; }
        
        ///<inheritdoc/>
        public EncryptionAlgorithm Algorithm { get; set; }

        private RSAEncryptionResult()
        {
        }

        /// <summary>
        /// Public Constructor
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="gcmNonce"></param>
        /// <param name="rsaPublicKey"></param>
        /// <param name="rsaSignature"></param>
        /// <param name="encryptionKey"></param>
        /// <param name="algorithm"></param>
        public RSAEncryptionResult(byte[] encryptedData, byte[] gcmNonce, byte[] rsaPublicKey, byte[] rsaSignature,
            byte[] encryptionKey, EncryptionAlgorithm algorithm)
        {
            EncryptedData = encryptedData;
            GcmNonce = gcmNonce;
            RSAPublicKey = rsaPublicKey;
            RSASignature = rsaSignature;
            EncryptionKey = encryptionKey;
            Algorithm = algorithm;
        }
        
        ///<inheritdoc/>
        public ReadOnlySpan<byte> Serialize()
        {
            return SerializeBson().ToArray();
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

        private static RSAEncryptionResult DeSerializeBinary(ReadOnlyMemory<byte> data)
        {
            RSAEncryptionResult result = new RSAEncryptionResult();
            
            using MemoryStream inputStream = new MemoryStream(data.ToArray());
            using BinaryReader reader = new BinaryReader(inputStream);
            
            int len = reader.ReadInt32();
            result.RSAPublicKey = reader.ReadBytes(len);
            
            len = reader.ReadInt32();
            result.RSASignature = reader.ReadBytes(len);
            
            len = reader.ReadInt32();
            result.EncryptionKey = reader.ReadBytes(len);
            
            len = reader.ReadInt32();
            if (len != -1)
                result.GcmNonce = reader.ReadBytes(len);
            
            result.Algorithm = (EncryptionAlgorithm)reader.ReadByte();
            
            len = reader.ReadInt32();
            result.EncryptedData = reader.ReadBytes(len);
            
            return result;
        }
        
        private static RSAEncryptionResult DeSerializeBson(ReadOnlyMemory<byte> data)
        {
            using MemoryStream inputStream = new MemoryStream(data.ToArray());
            using BinaryReader reader = new BinaryReader(inputStream);
            using BsonDataReader bsonDataReader = new BsonDataReader(reader);
            
            JsonSerializer serializer = new JsonSerializer();
            return serializer.Deserialize<RSAEncryptionResult>(bsonDataReader);
        }
        
        private static RSAEncryptionResult DeSerializeJson(ReadOnlyMemory<byte> data)
        {
            using MemoryStream inputStream = new MemoryStream(data.ToArray());
            using TextReader textReader = new StreamReader(inputStream);
            using JsonTextReader jsonReader = new JsonTextReader(textReader);
            
            JsonSerializer serializer = new JsonSerializer();
            
            return serializer.Deserialize<RSAEncryptionResult>(jsonReader);
        }
        
        private static RSAEncryptionResult DeSerializeXml(ReadOnlyMemory<byte> data)
        {
            XmlSerializer xmlSerializer = new XmlSerializer(typeof(RSAEncryptionResult));
            
            using MemoryStream inputStream = new MemoryStream(data.ToArray());
            using TextReader textReader = new StreamReader(inputStream);
            using XmlReader xmlReader = new XmlTextReader(textReader);
          
            return (RSAEncryptionResult)xmlSerializer.Deserialize(xmlReader);
        }
        
        private ReadOnlyMemory<byte> SerializeBinary()
        {
            using MemoryStream outputStream = new MemoryStream();
            using BinaryWriter writer = new BinaryWriter(outputStream);
            
            writer.Write(RSAPublicKey.Length);
            writer.Write(RSAPublicKey);
            
            writer.Write(RSASignature.Length);
            writer.Write(RSASignature);
            
            writer.Write(EncryptionKey.Length);
            writer.Write(EncryptionKey);

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
            serializer.Serialize(bsonDataWriter, this, typeof(RSAEncryptionResult));
            
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
            serializer.Serialize(jsonTextWriter, this, typeof(RSAEncryptionResult));
            
            jsonTextWriter.Flush();
            writer.Flush();
            
            return outputStream.ToArray();
        }
        
        private ReadOnlyMemory<byte> SerializeXml()
        {
            XmlSerializer xmlSerializer = new XmlSerializer(typeof(RSAEncryptionResult));
            using MemoryStream outputStream = new MemoryStream();
            using XmlTextWriter writer = new XmlTextWriter(outputStream, Encoding.UTF8);
            
            xmlSerializer.Serialize(writer, this);
            writer.Flush();
            
            return outputStream.ToArray();
        }
    }
}
