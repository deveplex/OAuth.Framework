using Deveplex.OAuth.Entity;
using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.OAuth.EntityFramework.Configurations
{
    public class AppConfiguration : OAuthEntityConfiguration<Client, string>
    {
        public AppConfiguration()
        {
            ToTable("Clients");
            HasKey(k => k.Id);

            Property(p => p.Id).HasColumnName("ID").HasMaxLength(256).IsRequired();//.HasDatabaseGeneratedOption(DatabaseGeneratedOption.Identity);
            Property(p => p.IsDeleted).HasColumnName("ISDEL").IsRequired();//.HasColumnAnnotation("default", 0);

            Property(p => p.OwnerId).HasColumnName("FKOWID").HasMaxLength(256).IsRequired();
            Property(p => p.UserName).HasColumnName("APPID").HasMaxLength(256).IsRequired();
            Property(p => p.PasswordHash).HasColumnName("SECRET").HasMaxLength(2046);
            Property(p => p.Name).HasColumnName("NAME").HasMaxLength(256);
            Property(p => p.CallbackUrl).HasColumnName("CBURL").HasMaxLength(2046);
            Property(p => p.Description).HasColumnName("DESC").HasMaxLength(512);
            Property(p => p.Status).HasColumnName("STATUS").HasColumnType("int").IsRequired();
            Property(p => p.CreatedDate).HasColumnName("CRDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);//.HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.ModifiedDate).HasColumnName("UPDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);//.HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.CheckCode).HasColumnName("CHECKHASH").HasMaxLength(256);

            HasIndex(ix => new { ix.UserName }).HasName("IX_CLIENTS_APPID").IsUnique(true).IsClustered(false);
            //HasIndex(ix => new { ix.Name }).HasName("IX_CLIENTS_NAME").IsUnique(true).IsClustered(false);

            //HasMany(u => u.Roles).WithOptional().HasForeignKey(uc => uc.UserId);
            //HasMany(m => m.Members).WithMany(n => n.Roles);
        }
    }
}
