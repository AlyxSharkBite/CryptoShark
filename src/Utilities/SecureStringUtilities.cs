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
        public String SecureStringToString(SecureString value)
        {
            IntPtr bstr = IntPtr.Zero;
            try
            {
                bstr = Marshal.SecureStringToBSTR(value);
                return Marshal.PtrToStringBSTR(bstr);
            }
            finally
            {
                if (bstr != IntPtr.Zero)
                    Marshal.ZeroFreeBSTR(bstr);
            }
        }

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

        public SecureString StringToSecureString(string value)
        {
            var secureString = new SecureString();
            foreach (var c in value.ToCharArray())
                secureString.AppendChar(c);

            secureString.MakeReadOnly();

            return secureString;
        }       
    }
}
