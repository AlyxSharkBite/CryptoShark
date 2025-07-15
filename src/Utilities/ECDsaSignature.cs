using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pqc.Crypto.Lms;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Utilities
{
    public sealed class ECDsaSignature
    {
        [JsonExtensionData]
        private IDictionary<string, JToken> _additionalData;

        [JsonIgnore]
        public BigInteger r { get; private set; }

        [JsonIgnore]
        public BigInteger s { get; private set; }

        public ECDsaSignature()
        {
            _additionalData = new Dictionary<string, JToken>();
        }

        public ECDsaSignature(BigInteger r, BigInteger s)
        {
            this.r = r;
            this.s = s;
            _additionalData = new Dictionary<string, JToken>();
        }

        public byte[] ToArray()
        {
            using MemoryStream bsonstream = new MemoryStream();
            using BinaryWriter binWriter = new BinaryWriter(bsonstream);
            using BsonDataWriter bsonDataWriter = new BsonDataWriter(binWriter);
            JsonSerializer serializer = new JsonSerializer();
            serializer.Serialize(bsonDataWriter, this, typeof(ECDsaSignature));

            return bsonstream.ToArray();
        }

        public static ECDsaSignature FromByteArray(byte[] data)
        {
            using MemoryStream bsonStream = new MemoryStream(data);
            using BinaryReader binReader = new BinaryReader(bsonStream);
            using BsonDataReader bsonDataReader = new BsonDataReader(binReader);
            JsonSerializer serializer = new JsonSerializer();

            return serializer.Deserialize<ECDsaSignature>(bsonDataReader);
        }

        [OnDeserialized]
        private void OnDeserialized(StreamingContext context)
        {
            r = new BigInteger((string)_additionalData["rVal"]);
            s = new BigInteger((string)_additionalData["sVal"]);
        }

        [OnSerializing]
        private void OnOnSerializing(StreamingContext context)
        {
            _additionalData["rVal"] = r.ToString();
            _additionalData["sVal"] = s.ToString();
        }
    }
}
