using Deveplex.Entity;
using Deveplex.Security.Providers;
using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Deveplex.Authentication.Entity
{
    public class Account : Account<string>, IEntity
    {
    }

    public class Account<TKey> : IEntity<TKey>, IIdentity<long>
        where TKey : IEquatable<TKey>
    {
        public long Id { get; set; }

        public TKey AccountId { get; set; }

        [Required]
        public string UserId { get; set; }

        [Required]
        public string UserName { get; set; }

        public string PasswordHash { get; set; }

        public virtual bool EmailConfirmed { get; set; }

        public virtual string SecurityStamp { get; set; }

        public virtual bool PhoneNumberConfirmed { get; set; }

        public virtual bool TwoFactorEnabled { get; set; }

        public virtual DateTime? LockoutEndDateUtc { get; set; }

        public virtual bool LockoutEnabled { get; set; }

        public virtual int AccessFailedCount { get; set; }

        public AccountStatus Status { get; set; }

        [DisplayFormat(DataFormatString = "yyyy-MM-dd HH:mm:ss")]
        public DateTime? CreatedDate { get; set; }

        [DisplayFormat(DataFormatString = "yyyy-MM-dd HH:mm:ss")]
        public DateTime? ModifiedDate { get; set; }

        //[Required]
        public string CheckCode { get; set; }

        public bool IsDeleted { get; set; }

        public string CheckString(IHashProvider provider = null)
        {
            string s = "";// $"SAID={(UserId ?? "NULL")}&SUID ={(UserName ?? "NULL")}&STATE={Status}";
            var b = System.Text.Encoding.Unicode.GetBytes(s);
            string hashStr = Convert.ToBase64String(b);
            return (provider == null) ? hashStr : provider.Hash(hashStr);
        }
    }

    public enum AccountStatus : int
    {
        //[DisplayName("启用")]
        [Description("启用")]
        Enabled = 0,

        //[DisplayName("禁用")]
        [Description("禁用")]
        Disabled = 1,

        //[DisplayName("禁用")]
        [Description("受限")]
        dddddd = 2,
    }
}
