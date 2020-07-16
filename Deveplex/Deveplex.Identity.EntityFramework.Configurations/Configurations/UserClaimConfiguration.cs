using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Identity.EntityFramework.Configurations
{
    public class UserClaimConfiguration : IdentityEntityConfiguration<IdentityUserClaim, string>
    {
        public UserClaimConfiguration()
        {
            ToTable("UserClaims");
            HasKey(k => k.Id);//.HasName("PK_USERCLAIMS")

            Property(p => p.Id).HasColumnName("ID").HasMaxLength(256).IsRequired();//.HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);
            Property(p => p.IsDeleted).HasColumnName("ISDEL").IsRequired();//.HasColumnAnnotation("default", 0);

            Property(p => p.UserId).HasColumnName("FKSGID").HasMaxLength(256).IsRequired();
            Property(p => p.ClaimType).HasColumnName("TYPE").HasMaxLength(256).IsRequired();
            Property(p => p.ClaimValue).HasColumnName("VALUE").HasMaxLength(2046).IsRequired();
            Property(p => p.ModifiedDate).HasColumnName("UPDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);//.HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.CheckCode).HasColumnName("CHECKHASH").HasMaxLength(256);

            HasIndex(ix => new { ix.UserId, ix.ClaimType }).HasName("IX_USERCLAIMS_SGID_TYPE").IsUnique(true).IsClustered(false);
            //HasMany(m => m.Members).WithMany(n => n.Roles);
        }
    }




}
