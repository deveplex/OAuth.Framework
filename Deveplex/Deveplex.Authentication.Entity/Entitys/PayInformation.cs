using Deveplex.Entity;
using Deveplex.Security.Providers;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Authentication.Entity
{
    public class PayInformation : PayInformation<string>, IEntity
    {

    }

    [Table("PayInfo")]
    public class PayInformation<TKey> : IEntity<TKey>, IIdentity<long>
        where TKey : IEquatable<TKey>
    {
        public long Id { get; set; }

        [Required]
        [Column("FKBGID")]
        public TKey BankId { get; set; }

        [Required]
        [Column("PAYKEY")]
        public string PayKey { get; set; }

        [DatabaseGenerated(DatabaseGeneratedOption.Computed)]
        [DisplayFormat(DataFormatString = "yyyy-MM-dd HH:mm:ss")]
        [Column("UPDATE")]
        public DateTime? ModifiedDate { get; set; }

        [Required]
        [Column("HASHKEY")]
        public string CheckCode { get; set; }

        public bool IsDeleted { get; set; }

        public string CheckString(IHashProvider provider = null)
        {
            string s = "";// $"FK_SGID={(AccountID ?? "NULL")}&ISRESET={IsResetPassword}&ISUID={IsResetUserID}&ISVRLN={IsValidName}&ISVEML={IsValidEmail}&ISVMBL={IsValidMobile}";
            var b = System.Text.Encoding.Unicode.GetBytes(s);
            string hashStr = Convert.ToBase64String(b);
            return (provider == null) ? hashStr : provider.Hash(hashStr);
        }
    }
}
