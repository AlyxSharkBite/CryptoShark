using CryptoShark.Interfaces;
using CSharpFunctionalExtensions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Utilities
{
    /// <summary>
    /// Encryption Record Serializer/Deserializer
    /// </summary>
    internal sealed class RecordSerializer(ILogger logger)
    {
        /// <summary>
        /// Serializes an Encryption Record 
        /// </summary>
        /// <typeparam name="T">IRecordMarker</typeparam>
        /// <param name="record">EccCryptographyRecord, PbeCryptographyRecord or RsaCryptographyRecord</param>
        /// <returns>Buffer With The Serialized Binary Data</returns>
        /// <example>
        /// <code>
        /// RecordSerializer recordSerializer = new RecordSerializer(logger);
        /// var serialized = recordSerializer.SerializeRecord<EccCryptographyRecord>(record);
        /// </code>
        /// </example>
        /// <exception cref="SerializationException"></exception>
        public ReadOnlyMemory<byte> SerializeRecord<T> (T record) 
            where T : IRecordMarker
        {
            var result = InternalSerialize(record);
            if (result.IsFailure)
                throw new SerializationException($"CryptoShark:RecordSerializer failed to serialize {record.GetType().Name}", result.Error);

            return new ReadOnlyMemory<byte>(result.Value);
        }

        /// <summary>
        /// Deserializes an Encryption Record 
        /// </summary>
        /// <typeparam name="T">IRecordMarker</typeparam>
        /// <param name="data">Serialized Binary Data</param>
        /// <example>
        /// <code>
        /// RecordSerializer recordSerializer = new RecordSerializer(logger);
        /// var record = recordSerializer.DeserializeRecord<EccCryptographyRecord>(binaryData);
        /// </code>
        /// </example>
        /// <returns>EccCryptographyRecord, PbeCryptographyRecord or RsaCryptographyRecord</returns>
        /// <exception cref="SerializationException"></exception>
        public T DeserializeRecord<T>(ReadOnlyMemory<byte> data)
           where T : IRecordMarker
        {
            var result = InternalDeserialize<T>(data);
            if (result.IsFailure)
                throw new SerializationException($"CryptoShark:RecordSerializer failed to deserialize {typeof(T).Name}", result.Error);           

            return result.Value;
        }

        private Result<byte[], Exception> InternalSerialize<T>(T record)
            where T : IRecordMarker
        {
            try
            {
                using MemoryStream stream = new MemoryStream();
                using BinaryWriter writer = new BinaryWriter(stream);
                using BsonDataWriter bsonDataWriter = new BsonDataWriter(writer);
                JsonSerializer serializer = new JsonSerializer();

                serializer.Serialize(bsonDataWriter, record, record.GetType());

                if(stream.Length <=0)
                    return Result.Failure<byte[], Exception>(new SerializationException("Could not serialize data"));

                return stream.ToArray();

            }
            catch (Exception ex) 
            {
                logger?.LogError(ex, "CryptoShark:RecordSerializer {message}", ex.Message);
                return Result.Failure<byte[], Exception>(ex);
            }
        }

        private Result<T, Exception> InternalDeserialize<T>(ReadOnlyMemory<byte> data)
            where T : IRecordMarker
        {
            try
            {
                using MemoryStream inputStream = new MemoryStream(data.ToArray());
                using BinaryReader reader = new BinaryReader(inputStream);
                using BsonDataReader bsonDataReader = new BsonDataReader(reader);

                JsonSerializer serializer = new JsonSerializer();
                var record = serializer.Deserialize<T>(bsonDataReader);

                if(record is null)
                    return Result.Failure<T, Exception>(new SerializationException("Could not eeserialize data"));

                return record;
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:RecordSerializer {message}", ex.Message);
                return Result.Failure<T, Exception>(ex);
            }
        }
    }
}
