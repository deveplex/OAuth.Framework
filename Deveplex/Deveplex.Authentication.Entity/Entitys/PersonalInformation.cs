using Deveplex.Entity;
using Deveplex.Security.Providers;
using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Authentication.Entity
{
    public class PersonalInformation : PersonalInformation<string>, IEntity
    {

    }

    [Table("Personal")]
    public class PersonalInformation<TKey> : IEntity<TKey>, IIdentity<long>
        where TKey : IEquatable<TKey>
    {
        public long Id { get; set; }

        [Required]
        [Column("FKSGID")]
        public TKey AccountId { get; set; }

        [Column("NICK")]
        public string NickName { get; set; }

        [Column("NAME")]
        public string Name { get; set; }

        [Column("SEX")]
        public SexTypes Sex { get; set; }

        [Column("BCLD")]
        public BirthdayTypes BirthdayType { get; set; }

        [Column("BTHD")]
        public DateTime? Birthday { get; set; }

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

        [Column("IM")]
        public string IM { get; set; }

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

        [Column("IDPH")]
        public string IDPath { get; set; }

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

    public enum SexTypes : int
    {
        [Description("未知")]
        None = 0,

        [Description("男")]
        Man = 1,

        [Description("女")]
        Women = 2,
    }

    public enum BirthdayTypes : int
    {
        [Description("公历")]
        GregorianCalendar = 0,

        [Description("农历")]
        LunarCalendar = 1,
    }
}
