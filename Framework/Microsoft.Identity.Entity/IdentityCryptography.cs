using System.ComponentModel;

namespace Microsoft.Identity
{
    public class IdentityCryptography<TKey> : ICryptography<TKey>
    {
        public virtual TKey UserId { get; set; }

        public virtual string PasswordHash { get; set; }

        public virtual string PrivateKey { get; set; }
    }
}
