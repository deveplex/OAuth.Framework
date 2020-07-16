
namespace Microsoft.AspNet.OAuth
{
    public class Scope<TKey> : IScope<TKey>
    {
        public virtual TKey Id { get; set; }

        public virtual string Name { get; set; }
    }
}
