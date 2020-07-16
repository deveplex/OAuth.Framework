using Deveplex.Entity;
using Microsoft.AspNet.Identity.Security.Providers;
using Microsoft.Identity;
using System;
using System.ComponentModel.DataAnnotations;

namespace Deveplex.OAuth
{
    public class ClientScope : ClientScope<string>, IEntity<string>
    {
        public string Id { get; set; }

        [DisplayFormat(DataFormatString = "yyyy-MM-dd HH:mm:ss")]
        public DateTime? ModifiedDate { get; set; }

        public string CheckCode { get; set; }

        public bool IsDeleted { get; set; }

        public string Signature(IHashProvider provider = null)
        {
            string s = "";// $"SGID={(AccountID ?? "NULL")}&PSWD={Password}&FMAT={Format}&V={Version.ToString("#.00")}&SALT={(UserKey ?? "NULL")}";
            var b = System.Text.Encoding.Unicode.GetBytes(s);
            string hashStr = Convert.ToBase64String(b);
            return (provider == null) ? hashStr : provider.Hash(hashStr);
        }
    }
    public class ClientScope<TKey> : IdentityUserRole<TKey>
    {
    }
}
