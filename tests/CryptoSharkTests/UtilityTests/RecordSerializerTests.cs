using CryptoShark.Record;
using CryptoShark.Utilities;
using Microsoft.Extensions.Logging;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.UtilityTests
{
    public class RecordSerializerTests
    {       
        private Mock<ILogger> _mockLogger;        

        [SetUp]
        public void Setup()
        {
            _mockLogger = new Mock<ILogger>();
        }

        [Test]
        public void TestEccCryptographyRecordSerialization()
        {
            RecordSerializer  recordSerializer = new RecordSerializer(_mockLogger.Object);

            var record = CreateEccCryptographyRecord();

            var data = recordSerializer.SerializeRecord<EccCryptographyRecord>(record);
            Assert.That(data.IsEmpty, Is.False);

            var newRecord = recordSerializer.DeserializeRecord<EccCryptographyRecord>(data);
            Assert.That(newRecord, Is.Not.Null);
            Assert.That(newRecord.PublicKey.SequenceEqual(record.PublicKey), Is.True);
            Assert.That(newRecord.Signature.SequenceEqual(record.Signature), Is.True);
            Assert.That(newRecord.EncryptedData.SequenceEqual(record.EncryptedData), Is.True);
            Assert.That(newRecord.Nonce.SequenceEqual(record.Nonce), Is.True);
            Assert.That(newRecord.EncryptionAlgorithm == record.EncryptionAlgorithm, Is.True);

        }

        [Test]
        public void TestPbeCryptographyRecordSerialization()
        {
            RecordSerializer recordSerializer = new RecordSerializer(_mockLogger.Object);

            var record = CreatePbeCryptographyRecord();

            var data = recordSerializer.SerializeRecord<PbeCryptographyRecord>(record);
            Assert.That(data.IsEmpty, Is.False);

            var newRecord = recordSerializer.DeserializeRecord<PbeCryptographyRecord>(data);
            Assert.That(newRecord, Is.Not.Null);
            Assert.That(newRecord.Hash.SequenceEqual(record.Hash), Is.True);
            Assert.That(newRecord.Salt.SequenceEqual(record.Salt), Is.True);
            Assert.That(newRecord.EncryptedData.SequenceEqual(record.EncryptedData), Is.True);
            Assert.That(newRecord.Nonce.SequenceEqual(record.Nonce), Is.True);
            Assert.That(newRecord.EncryptionAlgorithm == record.EncryptionAlgorithm, Is.True);
            Assert.That(newRecord.Iterations == record.Iterations, Is.True);

        }

        [Test]
        public void TestRsaCryptographyRecordSerialization()
        {
            RecordSerializer recordSerializer = new RecordSerializer(_mockLogger.Object);

            var record = CreateRsaCryptographyRecord();

            var data = recordSerializer.SerializeRecord<RsaCryptographyRecord>(record);
            Assert.That(data.IsEmpty, Is.False);

            var newRecord = recordSerializer.DeserializeRecord<RsaCryptographyRecord>(data);
            Assert.That(newRecord, Is.Not.Null);
            Assert.That(newRecord.EncryptionKey.SequenceEqual(record.EncryptionKey), Is.True);
            Assert.That(newRecord.PublicKey.SequenceEqual(record.PublicKey), Is.True);
            Assert.That(newRecord.Signature.SequenceEqual(record.Signature), Is.True);
            Assert.That(newRecord.EncryptedData.SequenceEqual(record.EncryptedData), Is.True);
            Assert.That(newRecord.Nonce.SequenceEqual(record.Nonce), Is.True);
            Assert.That(newRecord.EncryptionAlgorithm == record.EncryptionAlgorithm, Is.True);
        }

        private static EccCryptographyRecord CreateEccCryptographyRecord()
        {
            return new EccCryptographyRecord
            {
                EncryptionAlgorithm = CryptoShark.Enums.EncryptionAlgorithm.Aes,
                PublicKey = GenerateBytes(256),
                Signature = GenerateBytes(128),
                EncryptedData = GenerateBytes(4096),
                Nonce = GenerateBytes(16)
            };
        }

        private static PbeCryptographyRecord CreatePbeCryptographyRecord()
        {
            return new PbeCryptographyRecord
            {
                EncryptionAlgorithm = CryptoShark.Enums.EncryptionAlgorithm.Aes,
                EncryptedData = GenerateBytes(4096),
                Nonce = GenerateBytes(16),
                Hash = GenerateBytes(96),
                Iterations = 500,
                Salt = GenerateBytes(16)
            };
        }

        private static RsaCryptographyRecord CreateRsaCryptographyRecord()
        {
            return new RsaCryptographyRecord
            {
                EncryptionAlgorithm = CryptoShark.Enums.EncryptionAlgorithm.Aes,
                EncryptedData = GenerateBytes(4096),
                EncryptionKey = GenerateBytes(112),
                PublicKey = GenerateBytes(248),
                Signature = GenerateBytes(96),
                Nonce = GenerateBytes(16)
            };
        }

        private static byte[] GenerateBytes(int size)
        {
            var salt = new byte[size];
            using RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetNonZeroBytes(salt);

            return salt;
        }
    }
}
