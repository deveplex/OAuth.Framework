using Deveplex.OAuth.Entity;
using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.OAuth.EntityFramework.Configurations
{
    public class ClientScopeConfiguration : OAuthEntityConfiguration<ClientScope, string>
    {
        public ClientScopeConfiguration()
        {
            ToTable("ClientScopes");
            HasKey(k => k.Id);

            Property(p => p.Id).HasColumnName("ID").HasMaxLength(256).IsRequired();//.HasDatabaseGeneratedOption(DatabaseGeneratedOption.Identity);
            Property(p => p.IsDeleted).HasColumnName("ISDEL").IsRequired();//.HasColumnAnnotation("default", 0);

            Property(p => p.UserId).HasColumnName("FKSGID").HasMaxLength(256).IsRequired();
            Property(p => p.RoleId).HasColumnName("FKRGID").HasMaxLength(128).IsRequired();
            Property(p => p.ModifiedDate).HasColumnName("UPDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);//.HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.CheckCode).HasColumnName("CHECKHASH").HasMaxLength(256);

            HasIndex(ix => new { ix.UserId, ix.RoleId }).HasName("IX_CIIENTSCOPES_SGID_RGID").IsUnique(true).IsClustered(false);
            //HasMany(m => m.Members).WithMany(n => n.Roles);
        }
    }
}
