using System;
using System.Collections.Generic;

namespace Microsoft.AspNet.Identity.EntityFramework
{
    public class IdentityUser : IdentityUser<string>, IUser
    {
        public IdentityUser()
        {
        }
    }

    public class IdentityUser<TKey> : IdentityUser<TKey, IdentityUserLogin<TKey>, IdentityUserRole<TKey>, IdentityUserClaim<TKey>>, IUser<TKey>
        where TKey : IEquatable<TKey>
    {
        public IdentityUser()
        {
        }
        public virtual string Email { get; set; }
        public virtual bool EmailConfirmed { get; set; }
        public virtual string PhoneNumber { get; set; }
        public virtual bool PhoneNumberConfirmed { get; set; }
        public virtual string SecurityStamp { get; set; }
        public virtual bool TwoFactorEnabled { get; set; }
        public virtual DateTime? LockoutEndDateUtc { get; set; }
        public virtual bool LockoutEnabled { get; set; }
        public virtual int AccessFailedCount { get; set; }
    }

    public class IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim> : IUser<TKey>
        where TUserLogin : IdentityUserLogin<TKey>
        where TUserRole : IdentityUserRole<TKey>
        where TUserClaim : IdentityUserClaim<TKey>
        where TKey : IEquatable<TKey>
    {
        public IdentityUser()
        {
            Claims = new List<TUserClaim>();
            Roles = new List<TUserRole>();
            Logins = new List<TUserLogin>();
        }
        public virtual TKey Id { get; set; }
        public virtual string UserName { get; set; }
        public virtual ICollection<TUserLogin> Logins { get; private set; }
        public virtual ICollection<TUserRole> Roles { get; private set; }
        public virtual ICollection<TUserClaim> Claims { get; private set; }
    }

    public class IdentityUserLogin<TKey>
        where TKey : IEquatable<TKey>
    {
        public virtual string LoginProvider { get; set; }
        public virtual string ProviderKey { get; set; }
    }

    public class IdentityUserRole<TKey>
        where TKey : IEquatable<TKey>
    {
        public virtual TKey RoleId { get; set; }
    }

    public class IdentityUserClaim<TKey>
        where TKey : IEquatable<TKey>
    {
        public virtual string ClaimType { get; set; }
        public virtual string ClaimValue { get; set; }

    }
}
