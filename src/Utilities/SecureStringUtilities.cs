using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Utilities
{
    internal sealed class SecureStringUtilities
    {
        public char[] SecureStringToCharArray(SecureString value)
        {
            IntPtr bstr = IntPtr.Zero;
            try
            {
                bstr = Marshal.SecureStringToBSTR(value);
                return Marshal.PtrToStringBSTR(bstr).ToCharArray();
            }
            finally
            {
                if (bstr != IntPtr.Zero)
                    Marshal.ZeroFreeBSTR(bstr);
            }
        }

        public SecureString StringToSecureString(char[] value)
        {
            var secureString = new SecureString();
            foreach (var c in value)
                secureString.AppendChar(c);

            secureString.MakeReadOnly();

            return secureString;
        }       
    }
}
