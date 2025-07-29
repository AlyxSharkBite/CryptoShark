using CryptoShark.Interfaces;
using MessagePack;
using MessagePack.Resolvers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;

namespace CryptoShark.Utilities
{
    [MessagePackObject(true)]
    public class ECDsaSignature 
    {
        [Key(0)]
        public byte[] _r {  get; set; }

        [Key(1)]
        public byte[] _s { get; set; }

        [IgnoreMember]
        public BigInteger r => new BigInteger(_r);

        [IgnoreMember]
        public BigInteger s => new BigInteger(_s);     

        public ECDsaSignature()         
        { 
            _r = BigInteger.Zero.ToByteArray();
            _s = BigInteger.Zero.ToByteArray();
        }

        public ECDsaSignature(BigInteger r, BigInteger s)
        {
            this._r = r.ToByteArray();
            this._s = s.ToByteArray();           
        }

        public ECDsaSignature(byte[] r, byte[] s)
        {
            this._r = r;
            this._s = s;
        }

        public ReadOnlyMemory<byte> ToArray()
        {      
            var data = MessagePackSerializer.Serialize<ECDsaSignature>(this, 
                StandardResolverAllowPrivate.Options);           

            return new ReadOnlyMemory<byte>(data);
        }        

        public static ECDsaSignature FromByteArray(ReadOnlyMemory<byte> data) 
        {
            return MessagePackSerializer.Deserialize<ECDsaSignature>(
                data, 
                StandardResolverAllowPrivate.Options);
        }
    }
}
