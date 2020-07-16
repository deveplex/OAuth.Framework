using Deveplex.Entity;
using Microsoft.AspNet.Identity.Security.Providers;
using System;
using System.ComponentModel.DataAnnotations;

namespace Deveplex.OAuth.Entity
{
    public class ClientInformation : ClientInformation<string>, IEntity
    {
    }

    public class ClientInformation<TKey> : IEntity<TKey>
    {
        public TKey Id { get; set; }

        public string ClinetId { get; set; }// client_id

        public string Owner { get; set; }// 应用的所有者

        public string Email { get; set; }// 应用拥有者的email

        //public string Subject { get; set; }

        //public DateTime IssuedUtc { get; set; }

        //public DateTime ExpiresUtc { get; set; }

        //public string ProtectedTicket { get; set; }

        [DisplayFormat(DataFormatString = "yyyy-MM-dd HH:mm:ss")]
        public DateTime? ModifiedDate { get; set; }

        public string CheckCode { get; set; }

        public bool IsDeleted { get; set; }

        public string CheckString(IHashProvider provider = null)
        {
            string s = "";// $"SGID={(AccountID ?? "NULL")}&PSWD={Password}&FMAT={Format}&V={Version.ToString("#.00")}&SALT={(UserKey ?? "NULL")}";
            var b = System.Text.Encoding.Unicode.GetBytes(s);
            string hashStr = Convert.ToBase64String(b);
            return (provider == null) ? hashStr : provider.Hash(hashStr);
        }
    }
}
