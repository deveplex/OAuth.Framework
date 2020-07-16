
namespace Microsoft.AspNet.OAuth
{
    public class ClientScope<TKey> : IClientScope<TKey>
    {
        public virtual string ClientId { get; set; }

        public virtual string ScopeId { get; set; }
    }
}
