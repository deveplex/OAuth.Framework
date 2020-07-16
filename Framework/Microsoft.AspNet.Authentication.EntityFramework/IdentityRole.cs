using System;

namespace Microsoft.AspNet.Identity.EntityFramework
{
    public class IdentityRole : IdentityRole<string>, IRole
    {
        public string Description { get; set; }
        public string Remaek { get; set; }
    }

    public class IdentityRole<TKey> : IRole<TKey>
        where TKey : IEquatable<TKey>
    {
        public TKey Id { get; set; }
        public string Name { get; set; }
    }
}