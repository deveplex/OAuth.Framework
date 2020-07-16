using Deveplex.Authentication.Entity;
using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Authentication.EntityFramework.Configurations
{
    public class ExternalAccountConfiguration : AuthenticationEntityConfiguration<ExternalAccount, string>
    {
        public ExternalAccountConfiguration()
        {
            ToTable("exlogins");
            HasKey(k => k.Id);//.HasName("PK_EXTERNALACCOUNTS")

            Property(p => p.Id).HasColumnName("ID").HasDatabaseGeneratedOption(DatabaseGeneratedOption.Identity);
            Property(p => p.IsDeleted).HasColumnName("ISDEL").IsRequired().HasColumnAnnotation("default", 0);

            Property(p => p.AccountId).HasColumnName("FKSGID").HasMaxLength(256).IsRequired();
            Property(p => p.ProviderKey).HasColumnName("SXID").HasMaxLength(512).IsRequired();
            Property(p => p.ExternalProvider).HasColumnName("IDTYPE").HasMaxLength(50).IsRequired();
            Property(p => p.ModifiedDate).HasColumnName("UPDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed).HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.CheckCode).HasColumnName("HASHKEY").HasMaxLength(256);

            HasIndex(ix => new { ix.AccountId }).HasName("IX_EXTERNALACCOUNTS_SXID_IDTYPE").IsUnique(true).IsClustered(false);
            //HasMany(m => m.Members).WithMany(n => n.Roles);
        }
    }




}
