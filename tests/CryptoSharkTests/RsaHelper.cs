using CryptoShark.Enums;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests
{
    public class RsaKeyData
    {
        public RsaKeySize RsaKeySize { get; set; }
        public byte[] RsaPrivateKey { get; set; }
        public byte[] RsaPublicKey { get; set; }
    }


    public class RsaTestData
    {
        public RsaKeyData RsaKeyData { get; set; }
        public ILogger Logger { get; set; }
    }

    internal sealed class RsaHelper
    {
       public IReadOnlyList<RsaKeyData> RsaKeyData { get; private set; }

        public RsaHelper()
        {
            RsaKeyData =System.Text.Json.JsonSerializer.Deserialize<List<RsaKeyData>>(
                File.ReadAllText(Path.Combine(Environment.CurrentDirectory, "RsaTestData.json")));
        }
    }
}
