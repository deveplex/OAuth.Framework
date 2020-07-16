using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Identity.EntityFramework.Configurations
{
    public class RoleConfiguration : IdentityEntityConfiguration<IdentityRole, string>
    {
        public RoleConfiguration()
        {
            ToTable("Roles");
            HasKey(k => k.Id);//.HasName("PK_ROLES");

            Property(p => p.Id).HasColumnName("ID").HasMaxLength(256).IsRequired();//.HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);//.HasColumnAnnotation("default", "REPLACE(LTRIM(RTRIM(NEWID())),'-','')")
            Property(p => p.IsDeleted).HasColumnName("ISDEL").IsRequired();//.HasColumnAnnotation("default", 0);

            Property(p => p.RoleCode).HasColumnName("RAID").HasMaxLength(256);
            Property(p => p.Name).HasColumnName("NAME").HasMaxLength(256).IsRequired();
            Property(p => p.Description).HasColumnName("DESC").HasMaxLength(512);
            Property(p => p.Remaek).HasColumnName("REMAEK").HasMaxLength(256);
            Property(p => p.IsDefault).HasColumnName("ISDEF").IsRequired();//.HasColumnAnnotation("default", 0);
            Property(p => p.ModifiedDate).HasColumnName("UPDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);//.HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.CheckCode).HasColumnName("CHECKHASH").HasMaxLength(256);

            HasIndex(ix => new { ix.RoleCode }).HasName("IX_ROLES_RAID").IsUnique(true).IsClustered(false);
            HasIndex(ix => new { ix.Name }).HasName("IX_ROLES_NAME").IsUnique(true).IsClustered(false);
            //HasMany(m => m.Members).WithMany(n => n.Roles);
        }
    }




}
