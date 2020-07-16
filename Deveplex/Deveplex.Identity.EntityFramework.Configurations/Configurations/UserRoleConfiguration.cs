using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Identity.EntityFramework.Configurations
{
    public class UserRoleConfiguration : IdentityEntityConfiguration<IdentityUserRole, string>
    {
        public UserRoleConfiguration()
        {
            ToTable("UserRoles");
            HasKey(k => k.Id);//.HasName("PK_USERROLES")

            Property(p => p.Id).HasColumnName("ID").HasMaxLength(256).IsRequired();//.HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);
            Property(p => p.IsDeleted).HasColumnName("ISDEL").IsRequired();//.HasColumnAnnotation("default", 0);

            Property(p => p.UserId).HasColumnName("FKSGID").HasMaxLength(256).IsRequired();
            Property(p => p.RoleId).HasColumnName("FKRGID").HasMaxLength(256).IsRequired();
            Property(p => p.ModifiedDate).HasColumnName("UPDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed).HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.CheckCode).HasColumnName("CHECKHASH").HasMaxLength(256);

            HasIndex(ix => new { ix.UserId, ix.RoleId }).HasName("IX_USERROLES_SGID_RGID").IsUnique(true).IsClustered(false);
            //HasMany(m => m.Members).WithMany(n => n.Roles);
        }
    }




}
