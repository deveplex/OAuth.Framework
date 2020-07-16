
namespace Microsoft.Identity
{
    public class IdentityRole<TKey> : IRole<TKey>
    {
        public virtual TKey Id { get; set; }

        public virtual string Name { get; set; }
    }
}