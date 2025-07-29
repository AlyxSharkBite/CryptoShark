using CryptoShark.Interfaces;
using CSharpFunctionalExtensions;
using MessagePack;
using Microsoft.Extensions.Logging;
using System;
using System.Runtime.Serialization;

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

            return result.Value;
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

        private Result<ReadOnlyMemory<byte>, Exception> InternalSerialize<T>(T record)
            where T : IRecordMarker
        {
            try
            {
                return Result.Success<ReadOnlyMemory<byte>, Exception>(
                     MessagePackSerializer.Serialize<T>(record).AsMemory());     
            }
            catch (Exception ex) 
            {
                logger?.LogError(ex, "CryptoShark:RecordSerializer {message}", ex.Message);
                return Result.Failure<ReadOnlyMemory<byte>, Exception>(ex);
            }
        }

        private Result<T, Exception> InternalDeserialize<T>(ReadOnlyMemory<byte> data)
            where T : IRecordMarker
        {
            try
            {
                return Result.Success<T, Exception>(MessagePackSerializer.Deserialize<T>(data));
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "CryptoShark:RecordSerializer {message}", ex.Message);
                return Result.Failure<T, Exception>(ex);
            }
        }
    }
}
