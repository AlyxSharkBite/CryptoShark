using CryptoShark.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Options
{
    public class EccKeyParameters : IAsymmetricKeyParameter, IDisposable
    {
        public SecureString Password {  get; init; }
        public ECCurve Curve { get; init; }

        public EccKeyParameters(char[] password, ECCurve curve)
        {
            Password = new SecureString();
            foreach(var c in password)
                Password.AppendChar(c);

            Password.MakeReadOnly();

            Array.Clear(password);

            Curve = curve;
        }

        public void Dispose()
        {
            Password.Dispose();
        }
    }
}
