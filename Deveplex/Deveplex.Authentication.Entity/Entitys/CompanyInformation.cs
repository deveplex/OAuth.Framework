using Deveplex.Entity;
using Deveplex.Security.Providers;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Authentication.Entity
{
    public class CompanyInformation : CompanyInformation<string>, IEntity
    {

    }

    [Table("Company")]
    public class CompanyInformation<TKey> : IEntity<TKey>, IIdentity<long>
        where TKey : IEquatable<TKey>
    {
        public long Id { get; set; }

        [Required]
        [Column("FKSGID")]
        public TKey AccountId { get; set; }

        [Required]
        [Column("NAME")]
        public string CompanyName { get; set; }

        [Required]
        [Column("CODE")]
        public string CompanyCode { get; set; }

        [Required]
        [Column("PSTN")]
        public string LegalPerson { get; set; }

        [Column("HMPG")]
        public string HomePage { get; set; }

        [Column("EML")]
        public string Email { get; set; }

        [Column("MBL")]
        public string Mobile { get; set; }

        [Column("TEL")]
        public string Telephone { get; set; }

        [Column("FAX")]
        public string Fax { get; set; }

        [Column("OPRN")]
        public string ScopeOfBusiness { get; set; }

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

        [Column("VT")]
        public byte[] Image { get; set; }

        [Column("VTPH")]
        public string ImagePath { get; set; }

        [Column("CCPH")]
        public string CallingCardPath { get; set; }

        [DatabaseGenerated(DatabaseGeneratedOption.Computed)]
        [DisplayFormat(DataFormatString = "yyyy-MM-dd HH:mm:ss")]
        [Column("UPDATE")]
        public DateTime? ModifiedDate { get; set; }

        //[Required]
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
