using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace Microsoft.Identity
{
    public class IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim> : IdentityUser<TKey, TUserRole>, IUser<TKey>
        where TUserLogin : IdentityUserLogin<TKey>
        where TUserRole : IdentityUserRole<TKey>
        where TUserClaim : IdentityUserClaim<TKey>
    {
        public IdentityUser()
        {
            //Claims = new List<TUserClaim>();
            //Logins = new List<TUserLogin>();
        }

        public virtual string Email { get; set; }
        public virtual bool EmailConfirmed { get; set; }
        public virtual string PhoneNumber { get; set; }
        public virtual bool PhoneNumberConfirmed { get; set; }
        public virtual string SecurityStamp { get; set; }
        public virtual bool TwoFactorEnabled { get; set; }
        public virtual DateTime? LockoutEndDate { get; set; }
        public virtual bool LockoutEnabled { get; set; }
        public virtual int AccessFailedCount { get; set; }

        //public virtual ICollection<TUserLogin> Logins { get; private set; }
        //public virtual ICollection<TUserClaim> Claims { get; private set; }
    }

    public class IdentityUser<TKey, TUserRole> : IUser<TKey>
         where TUserRole : IdentityUserRole<TKey>
    {
        public IdentityUser()
        {
            //Roles = new List<TUserRole>();
        }

        public virtual TKey Id { get; set; }

        public virtual string UserName { get; set; }

        public virtual string PasswordHash { get; set; }

        //public virtual ICollection<TUserRole> Roles { get; private set; }
    }
}
