using Deveplex.Entity;
using Deveplex.Security.Providers;
using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Deveplex.Authentication.Entity
{
    public class ExternalAccount : ExternalAccount<string>, IEntity
    {

    }

    public class ExternalAccount<TKey> : IEntity<TKey>, IIdentity<long>
        where TKey : IEquatable<TKey>
    {
        public long Id { get; set; }

        [Required]
        public TKey AccountId { get; set; }

        [Required]
        public string ProviderKey { get; set; }

        [Required]
        public string ExternalProvider { get; set; }

        [DisplayFormat(DataFormatString = "yyyy-MM-dd HH:mm:ss")]
        public DateTime? ModifiedDate { get; set; }

        public string CheckCode { get; set; }

        public bool IsDeleted { get; set; }

        public string CheckString(IHashProvider provider = null)
        {
            string s = $"FKSGID={(AccountId)}&SXID={(ProviderKey ?? "NULL")}&IDTYPE={ExternalProvider}";
            var b = System.Text.Encoding.Unicode.GetBytes(s);
            string hashStr = Convert.ToBase64String(b);
            return (provider == null) ? hashStr : provider.Hash(hashStr);
        }
    }

    public static class ExternalProviders
    {
        //[DisplayName("")]
        [Description("用户名")]
        public const string UserName = "UserName";
        [Description("电子邮箱")]
        public const string Email = "Email";
        [Description("手机号")]
        public const string Mobile = "PhoneNumber";
        [Description("身份证")]
        public const string PID = "PID";
        [Description("QQ")]
        public const string QQ = "4";
        [Description("微信")]
        public const string Weixin = "5";
        [Description("淘宝")]
        public const string Taobao = "6";
        [Description("支付宝")]
        public const string AliPay = "7";
        [Description("微博")]
        public const string Weibo = "8";
    }
}
