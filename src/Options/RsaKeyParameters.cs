using CryptoShark.Enums;
using CryptoShark.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Options
{
    public class RsaKeyParameters : IAsymmetricKeyParameter, IDisposable
    {
        public SecureString Password { get; init; }
        public RsaKeySize KeySize { get; init; }

        public RsaKeyParameters(string password, RsaKeySize keySize)
        {
            Password = new SecureString();
            foreach (var c in password.ToCharArray())
                Password.AppendChar(c);

            Password.MakeReadOnly();

            KeySize = keySize;
        }

        public void Dispose()
        {
            Password.Dispose();
        }
    }
}
