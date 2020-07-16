
using System.Collections.Generic;

namespace Microsoft.AspNet.OAuth
{
    public class Client<TKey> : Client<TKey, IClientScope<TKey>>
    {
        public virtual TKey UserId { get; set; }

        public virtual string CallbackUrl { get; set; }
    }

    public class Client<TKey, TClientScope> : IClient<TKey>
         where TClientScope : IClientScope<TKey>
    {
        public virtual TKey Id { get; set; }

        public virtual string ClientName { get; set; }

        public virtual string Secret { get; set; }

        public virtual ICollection<TClientScope> Scopes { get; private set; }
    }
}
