using Deveplex.Entity;
using Microsoft.AspNet.Identity.Security.Providers;
using Microsoft.Identity;
using System;
using System.ComponentModel.DataAnnotations;

namespace Deveplex.OAuth
{
    public class Scope : Scope<string>, IEntity<string>
    {
        public virtual string RoleCode { get; set; }

        public virtual string Description { get; set; }

        public virtual string Remaek { get; set; }

        public virtual bool IsDefault { get; set; }

        public virtual DateTime? ModifiedDate { get; set; }

        public virtual string CheckCode { get; set; }

        public bool IsDeleted { get; set; }

        public string Signature(IHashProvider provider = null)
        {
            string s = "";// $"SGID={(AccountID ?? "NULL")}&PSWD={Password}&FMAT={Format}&V={Version.ToString("#.00")}&SALT={(UserKey ?? "NULL")}";
            var b = System.Text.Encoding.Unicode.GetBytes(s);
            string hashStr = Convert.ToBase64String(b);
            return (provider == null) ? hashStr : provider.Hash(hashStr);
        }
    }

    public class Scope<TKey> : IdentityRole<TKey>
    {
    }
}
