using System.ComponentModel;

namespace Microsoft.AspNet.Identity
{
    public class IdentityCryptography<TKey> : ICryptography<TKey>
    {
        public virtual TKey UserId { get; set; }

        public virtual string PasswordHash { get; set; }

        public virtual string PrivateHash { get; set; }
    }
}
