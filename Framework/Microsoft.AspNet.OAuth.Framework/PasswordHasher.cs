using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.OAuth
{
    internal class PasswordHasher : IPasswordHasher
    {
        public virtual string HashPassword(string password)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            return password;
        }
    }

    /*
    internal static class PasswordHasher
    {
        public static string GenerateSalt()
        {
            return Convert.ToBase64String(Guid.NewGuid().ToByteArray());
        }

        public static string HashPassword(string password)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            var hash = Crypto.HashPassword(password);
            return hash.Replace("-", "");
        }

        public static string HashPassword(string password, string userKey)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            if (userKey == null)
            {
                throw new ArgumentNullException("userKey");
            }
            if (userKey.Length < 8)
            {
                throw new ArgumentException("The userKey size must be 8 bytes and larger");
            }

            return Crypto.HashPassword(password, Encoding.UTF8.GetBytes(userKey));
        }
    }*/
}
