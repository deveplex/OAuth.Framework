using Deveplex.Authentication.Entity;
using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Authentication.EntityFramework.Configurations
{
    public class AccountAttributeConfiguration : AuthenticationEntityConfiguration<AccountAttribute, string>
    {
        public AccountAttributeConfiguration()
        {
            ToTable("attributes");
            HasKey(k => k.Id);//.HasName("PK_ACCOUNTATTRIBUTES")

            Property(p => p.Id).HasColumnName("ID").HasDatabaseGeneratedOption(DatabaseGeneratedOption.Identity);
            Property(p => p.IsDeleted).HasColumnName("ISDEL").IsRequired().HasColumnAnnotation("default", 0);

            Property(p => p.AccountId).HasColumnName("FKSGID").HasMaxLength(256).IsRequired();
            Property(p => p.AccountType).HasColumnName("TYPE").HasColumnType("int").IsRequired();
            Property(p => p.IsResetUserName).HasColumnName("ISUID").IsRequired().HasColumnAnnotation("default", 0);
            Property(p => p.IsResetPassword).HasColumnName("ISRESET").IsRequired().HasColumnAnnotation("default", 0);
            Property(p => p.NameIsValidated).HasColumnName("ISVRLN").IsRequired().HasColumnAnnotation("default", 0);
            Property(p => p.EmailIsValidated).HasColumnName("ISVEML").IsRequired().HasColumnAnnotation("default", 0);
            Property(p => p.MobileIsValidated).HasColumnName("ISVMBL").IsOptional().HasColumnAnnotation("default", 0);
            Property(p => p.ZuluTime).HasColumnName("ZULU").IsRequired().HasColumnAnnotation("default", 0);
            Property(p => p.ModifiedDate).HasColumnName("UPDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed).HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.CheckCode).HasColumnName("HASHKEY").HasMaxLength(256);

            HasIndex(ix => new { ix.AccountId }).HasName("IX_ACCOUNTATTRIBUTES_SGID").IsUnique(true).IsClustered(false);
            //HasMany(m => m.Members).WithMany(n => n.Roles);
        }
    }




}
