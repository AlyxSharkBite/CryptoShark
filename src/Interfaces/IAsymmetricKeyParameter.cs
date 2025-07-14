using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Interfaces
{
    public interface IAsymmetricKeyParameter
    {
        SecureString Password { get; }
    }

}
