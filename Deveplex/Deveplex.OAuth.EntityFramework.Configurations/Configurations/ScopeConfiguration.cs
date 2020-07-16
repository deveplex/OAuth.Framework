using Deveplex.OAuth.Entity;
using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.OAuth.EntityFramework.Configurations
{
    public class ScopeConfiguration : OAuthEntityConfiguration<Scope, string>
    {
        public ScopeConfiguration()
        {
            ToTable("Scopes");
            HasKey(k => k.Id);

            Property(p => p.Id).HasColumnName("ID").HasMaxLength(256).IsRequired();//.HasDatabaseGeneratedOption(DatabaseGeneratedOption.Identity);
            Property(p => p.IsDeleted).HasColumnName("ISDEL").IsRequired();//.HasColumnAnnotation("default", 0);

            Property(p => p.RoleCode).HasColumnName("RAID").HasMaxLength(256);
            Property(p => p.Name).HasColumnName("SCOPE").HasMaxLength(256).IsRequired();
            Property(p => p.Description).HasColumnName("DESC").HasMaxLength(512);
            Property(p => p.Remaek).HasColumnName("REMAEK").HasMaxLength(256);
            Property(p => p.IsDefault).HasColumnName("ISDEF").IsRequired();//.HasColumnAnnotation("default", 0);
            Property(p => p.ModifiedDate).HasColumnName("UPDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);//.HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.CheckCode).HasColumnName("CHECKHASH").HasMaxLength(256);

            HasIndex(ix => new { ix.Name }).HasName("IX_SCOPES_SCOPE").IsUnique(true).IsClustered(false);
            //HasMany(m => m.Members).WithMany(n => n.Roles);
        }
    }
}
