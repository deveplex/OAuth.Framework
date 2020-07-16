using Deveplex.Entity;
using Microsoft.AspNet.Identity.Security.Providers;
using Microsoft.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace Deveplex.Identity
{
    public class IdentityUser : IdentityUser<string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>, IEntity, IUser
    {
        public IdentityUser()
        {
            Id = Guid.NewGuid().ToString("N");
        }
        public virtual string UserCode { get; set; }

        public virtual AccountStatus Status { get; set; }

        public virtual DateTime? CreatedDate { get; set; }

        //[DisplayFormat(DataFormatString = "yyyy-MM-dd HH:mm:ss")]
        public virtual DateTime? ModifiedDate { get; set; }

        public virtual string CheckCode { get; set; }

        public virtual bool IsDeleted { get; set; }

        public string Signature(IHashProvider provider = null)
        {
            string s = "";// $"SGID={(AccountID ?? "NULL")}&PSWD={Password}&FMAT={Format}&V={Version.ToString("#.00")}&SALT={(UserKey ?? "NULL")}";
            var b = System.Text.Encoding.Unicode.GetBytes(s);
            string hashStr = Convert.ToBase64String(b);
            return (provider == null) ? hashStr : provider.Hash(hashStr);
        }
    }

    public enum AccountStatus : int
    {
        //[DisplayName("启用")]
        [Description("启用")]
        Enabled = 0x00,

        //[DisplayName("禁用")]
        [Description("受限")]
        dddddd = 0xF0,

        //[DisplayName("禁用")]
        [Description("禁用")]
        Disabled = 0xFF,
    }
}
