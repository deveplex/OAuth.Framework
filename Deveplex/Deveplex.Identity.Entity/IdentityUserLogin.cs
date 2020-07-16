
using Deveplex.Entity;
using Microsoft.AspNet.Identity.Security.Providers;
using Microsoft.Identity;
using System;

namespace Deveplex.Identity
{
    public class IdentityUserLogin : IdentityUserLogin<string>, IEntity
    {
        public IdentityUserLogin()
        {
            Id = Guid.NewGuid().ToString("N");
        }
        public virtual string Id { get; set; }

        //[DisplayFormat(DataFormatString = "yyyy-MM-dd HH:mm:ss")]
        public virtual DateTime? ModifiedDate { get; set; }

        public virtual string CheckCode { get; set; }

        public virtual bool IsDeleted { get; set; }

        public string Signature(IHashProvider provider = null)
        {
            string s = "";// $"FKSGID={(AccountID ?? "NULL")}&PSWD={Password}&FMAT={Format}&V={Version.ToString("#.00")}&SALT={(UserKey ?? "NULL")}";
            var b = System.Text.Encoding.Unicode.GetBytes(s);
            string hashStr = Convert.ToBase64String(b);
            return (provider == null) ? hashStr : provider.Hash(hashStr);
        }
    }
}