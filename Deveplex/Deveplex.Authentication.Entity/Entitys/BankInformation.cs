using Deveplex.Entity;
using Deveplex.Security.Providers;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Authentication.Entity
{
    public class BankInformation : BankInformation<string>, IEntity
    {

    }

    [Table("BankInfo")]
    public class BankInformation<TKey> : IEntity<TKey>, IIdentity<long>
        where TKey : IEquatable<TKey>
    {
        public long Id { get; set; }

        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [Column("BGID")]
        public TKey BankId { get; set; }

        [Required]
        [Column("FKSGID")]
        public TKey AccountId { get; set; }

        [Required]
        [Column("BANK")]
        public string BankName { get; set; }

        [Required]
        [Column("NAME")]
        public string BankOfDeposit { get; set; }

        [Required]
        [Column("CARD")]
        public string CardNumber { get; set; }

        [Required]
        [Column("PID")]
        public string IdentityNumber { get; set; }

        [Column("MBL")]
        public string Mobile { get; set; }

        [Column("EML")]
        public string Email { get; set; }

        [Required]
        [Column("EXPDT")]
        public DateTime? ExpireDate { get; set; }

        [Column("CNTR")]
        public string Country { get; set; }

        [Column("PROV")]
        public string Province { get; set; }

        [Column("CITY")]
        public string City { get; set; }

        [Column("AREA")]
        public string Area { get; set; }

        [Column("TOWN")]
        public string Town { get; set; }

        [Column("ADDR")]
        public string Address { get; set; }

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
            string s = "";// $"FKSGID={(AccountID ?? "NULL")}&ISRESET={IsResetPassword}&ISUID={IsResetUserID}&ISVRLN={IsValidName}&ISVEML={IsValidEmail}&ISVMBL={IsValidMobile}";
            var b = System.Text.Encoding.Unicode.GetBytes(s);
            string hashStr = Convert.ToBase64String(b);
            return (provider == null) ? hashStr : provider.Hash(hashStr);
        }
    }
}
