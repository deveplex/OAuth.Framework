using Deveplex.Entity;
using Microsoft.AspNet.Identity.Security.Providers;
using Microsoft.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Deveplex.OAuth
{
    public class Client : Client<string, ClientScope>, IEntity, IUser
    {
        public Client()
        {
            Id = Guid.NewGuid().ToString("N");
        }
        public virtual string Description { get; set; }// 应用描述

        public virtual ClientStatus Status { get; set; }// 应用状态

        [DisplayFormat(DataFormatString = "yyyy-MM-dd HH:mm:ss")]
        public virtual DateTime? CreatedDate { get; set; }

        [DisplayFormat(DataFormatString = "yyyy-MM-dd HH:mm:ss")]
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

    public class Client<TKey, TClientScope> : IdentityUser<TKey, TClientScope>, IUser<TKey>
        where TClientScope : IdentityUserRole<TKey>
    {
        public virtual TKey OwnerId { get; set; }

        public virtual string Name { get; set; }// 应用名称

        public virtual string CallbackUrl { get; set; }
    }

    public enum ClientStatus : int
    {
        //[DisplayName("启用")]
        [Description("启用")]
        Enabled = 0x00,

        //[DisplayName("未通过审核")]
        [Description("未通过审核")]
        Reject = 0xF0,

        //[DisplayName("禁用")]
        [Description("禁用")]
        Disabled = 0xFF,
    }
}
