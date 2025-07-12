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
    public sealed class PBEncryptionResult : IEncryptionResult
    {
        /// <summary>
        ///     SHA384 HMAC Hash of the Unencrypted Data        
        /// </summary>
        public byte[] Sha384Hmac { get;  set; }

        /// <summary>
        ///     Salt used in the PBKDF2 Key Derivation
        /// </summary>
        public byte[] PbkdfSalt { get;  set; }

        /// <summary>
        ///     Number of iterations used in the
        ///     PBKDF2 Password Derivation 
        /// </summary>
        public int Iterations { get;  set; }

        ///<inheritdoc/>
        public byte[] EncryptedData { get;  set; }
        
        ///<inheritdoc/>
        public byte[] GcmNonce { get;  set; }
        
        ///<inheritdoc/>
        public EncryptionAlgorithm Algorithm { get;  set; }

        private PBEncryptionResult()
        {
        }

        /// <summary>
        /// Public Constructor
        /// </summary>
        /// <param name="sha384Hmac"></param>
        /// <param name="pbkdfSalt"></param>
        /// <param name="encryptedData"></param>
        /// <param name="gcmNonce"></param>
        /// <param name="encryptionAlgorithm"></param>
        /// <param name="iterations"></param>
        public PBEncryptionResult(byte[] sha384Hmac, byte[] pbkdfSalt,
            byte[] encryptedData, byte[] gcmNonce, EncryptionAlgorithm encryptionAlgorithm, int iterations)
        {
            Sha384Hmac = sha384Hmac;
            PbkdfSalt = pbkdfSalt;
            EncryptedData = encryptedData;
            GcmNonce = gcmNonce;
            Algorithm = encryptionAlgorithm;
            Iterations = iterations;
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

         private static PBEncryptionResult DeSerializeBinary(ReadOnlyMemory<byte> data)
        {
            PBEncryptionResult result = new PBEncryptionResult();
            
            using MemoryStream inputStream = new MemoryStream(data.ToArray());
            using BinaryReader reader = new BinaryReader(inputStream);
            
            int len = reader.ReadInt32();
            result.Sha384Hmac = reader.ReadBytes(len);
            
            len = reader.ReadInt32();
            result.PbkdfSalt = reader.ReadBytes(len);
            
            result.Iterations = reader.ReadInt32();
            
            len = reader.ReadInt32();
            if (len != -1)
                result.GcmNonce = reader.ReadBytes(len);
            
            result.Algorithm = (EncryptionAlgorithm)reader.ReadByte();
            
            len = reader.ReadInt32();
            result.EncryptedData = reader.ReadBytes(len);
            
            return result;
        }
        
        private static PBEncryptionResult DeSerializeBson(ReadOnlyMemory<byte> data)
        {
            using MemoryStream inputStream = new MemoryStream(data.ToArray());
            using BinaryReader reader = new BinaryReader(inputStream);
            using BsonDataReader bsonDataReader = new BsonDataReader(reader);
            
            JsonSerializer serializer = new JsonSerializer();
            return serializer.Deserialize<PBEncryptionResult>(bsonDataReader);
        }
        
        private static PBEncryptionResult DeSerializeJson(ReadOnlyMemory<byte> data)
        {
            using MemoryStream inputStream = new MemoryStream(data.ToArray());
            using TextReader textReader = new StreamReader(inputStream);
            using JsonTextReader jsonReader = new JsonTextReader(textReader);
            
            JsonSerializer serializer = new JsonSerializer();
            
            return serializer.Deserialize<PBEncryptionResult>(jsonReader);
        }
        
        private static PBEncryptionResult DeSerializeXml(ReadOnlyMemory<byte> data)
        {
            XmlSerializer xmlSerializer = new XmlSerializer(typeof(PBEncryptionResult));
            
            using MemoryStream inputStream = new MemoryStream(data.ToArray());
            using TextReader textReader = new StreamReader(inputStream);
            using XmlReader xmlReader = new XmlTextReader(textReader);
          
            return (PBEncryptionResult)xmlSerializer.Deserialize(xmlReader);
        }
        
        private ReadOnlyMemory<byte> SerializeBinary()
        {
            using MemoryStream outputStream = new MemoryStream();
            using BinaryWriter writer = new BinaryWriter(outputStream);
            
           writer.Write(Sha384Hmac.Length);
           writer.Write(Sha384Hmac);
           
           writer.Write(PbkdfSalt.Length);
           writer.Write(PbkdfSalt);
           
           writer.Write(Iterations);
           
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
            serializer.Serialize(bsonDataWriter, this, typeof(PBEncryptionResult));
            
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
            serializer.Serialize(jsonTextWriter, this, typeof(PBEncryptionResult));
            
            jsonTextWriter.Flush();
            writer.Flush();
            
            return outputStream.ToArray();
        }
        
        private ReadOnlyMemory<byte> SerializeXml()
        {
            XmlSerializer xmlSerializer = new XmlSerializer(typeof(PBEncryptionResult));
            using MemoryStream outputStream = new MemoryStream();
            using XmlTextWriter writer = new XmlTextWriter(outputStream, Encoding.UTF8);
            
            xmlSerializer.Serialize(writer, this);
            writer.Flush();
            
            return outputStream.ToArray();
        }
        
    }
}
