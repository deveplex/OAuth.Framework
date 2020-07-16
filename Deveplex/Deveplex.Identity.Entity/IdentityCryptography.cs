
using Deveplex.Entity;
using Microsoft.AspNet.Identity.Security.Providers;
using Microsoft.Identity;
using System;
using System.ComponentModel;

namespace Deveplex.Identity
{
    public class IdentityCryptography : IdentityCryptography<string>, IEntity, ICryptography
    {
        public IdentityCryptography()
        {
            Id = Guid.NewGuid().ToString("N");
        }
        public virtual string Id { get; set; }

        public virtual int Format { get; set; }

        public virtual decimal Version { get; set; }

        public virtual DateTime? ModifiedDate { get; set; }

        public virtual string CheckCode { get; set; }

        public virtual bool IsDeleted { get; set; }

        public string Signature(IHashProvider provider = null)
        {
            string s = "";// $"FKSGID={(AccountId)}&PSWD={Password}&FMAT={Format}&V={Version.ToString("#.00")}&SALT={(PrivateKey  ?? "NULL")}";
            var b = System.Text.Encoding.Unicode.GetBytes(s);
            string hashStr = Convert.ToBase64String(b);
            return (provider == null) ? hashStr : provider.Hash(hashStr);
        }
    }

    public enum CryptoFormats : int
    {
        //[DisplayName("MD5")]
        [Description("MD5")]
        MD5 = 0,
        SHA = 1,
        DES = 2,
        AES = 3,
    }
}
