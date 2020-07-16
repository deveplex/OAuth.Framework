using Deveplex.Entity;
using Deveplex.Security.Providers;
using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Deveplex.Authentication.Entity
{
    public class AccountAttribute : AccountAttribute<string>, IEntity
    {
    }

    public class AccountAttribute<TKey> : IEntity<TKey>, IIdentity<long>
        where TKey : IEquatable<TKey>
    {
        public long Id { get; set; }

        [Required]
        public TKey AccountId { get; set; }

        public AccountTypes AccountType { get; set; }

        public bool IsResetPassword { get; set; }

        public bool IsResetUserName { get; set; }

        public bool NameIsValidated { get; set; }

        public bool EmailIsValidated { get; set; }

        public bool MobileIsValidated { get; set; }

        public int ZuluTime { get; set; }

        [DisplayFormat(DataFormatString = "yyyy-MM-dd HH:mm:ss")]
        public DateTime? ModifiedDate { get; set; }

        //[Required]
        public string CheckCode { get; set; }

        public bool IsDeleted { get; set; }

        public string CheckString(IHashProvider provider = null)
        {
            string s = $"FKSGID={(AccountId)}&TYPE={AccountType}&ISRESET={IsResetPassword}&ISSETUID={IsResetUserName}&ISVRLN={NameIsValidated}&ISVEML={EmailIsValidated}&ISVMBL={MobileIsValidated}";
            var b = System.Text.Encoding.Unicode.GetBytes(s);
            string hashStr = Convert.ToBase64String(b);
            return (provider == null) ? hashStr : provider.Hash(hashStr);
        }
    }
    public enum AccountTypes : int
    {
        //[DisplayName("个人用户")]
        [Description("个人用户")]
        Person = 0,

        //[DisplayName("企业用户")]
        [Description("企业用户")]
        Enterprise = 1
    }

}
