using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Identity.EntityFramework.Configurations
{
    public class UserLoginConfiguration : IdentityEntityConfiguration<IdentityUserLogin, string>
    {
        public UserLoginConfiguration()
        {
            ToTable("UserLogins");
            HasKey(k => k.Id);//.HasName("PK_USERLOGINS")

            Property(p => p.Id).HasColumnName("ID").HasMaxLength(256).IsRequired();//.HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);
            Property(p => p.IsDeleted).HasColumnName("ISDEL").IsRequired();//.HasColumnAnnotation("default", 0);

            Property(p => p.UserId).HasColumnName("FKSGID").HasMaxLength(256).IsRequired();
            Property(p => p.ProviderKey).HasColumnName("AUTHKEY").HasMaxLength(512).IsRequired();
            Property(p => p.LoginProvider).HasColumnName("PROVIDER").HasMaxLength(256).IsRequired();
            Property(p => p.ModifiedDate).HasColumnName("UPDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);//.HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.CheckCode).HasColumnName("CHECKHASH").HasMaxLength(256);

            HasIndex(ix => new { ix.LoginProvider, ix.ProviderKey }).HasName("IX_USERLOGINS_PROVIDER_AUTHKEY").IsUnique(true).IsClustered(false);
            //HasMany(m => m.Members).WithMany(n => n.Roles);
        }


    }

}
