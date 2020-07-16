using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Identity.EntityFramework.Configurations
{
    public class CryptographyConfiguration : IdentityEntityConfiguration<IdentityCryptography, string>
    {
        public CryptographyConfiguration()
        {
            ToTable("Cryptos");
            HasKey(k => k.Id);//.HasName("PK_CRYPTOGRAPHY")

            Property(p => p.Id).HasColumnName("ID").HasMaxLength(256);//.HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);
            Property(p => p.IsDeleted).HasColumnName("ISDEL").IsRequired();//.HasColumnAnnotation("default", 0);

            Property(p => p.UserId).HasColumnName("FKSGID").HasMaxLength(256).IsRequired();
            Property(p => p.PasswordHash).HasColumnName("PWDHASH").HasMaxLength(2046);
            Property(p => p.Format).HasColumnName("F").HasColumnType("int").IsRequired();
            Property(p => p.Version).HasColumnName("V").HasColumnType("decimal").HasPrecision(10, 3).IsRequired();//.HasColumnAnnotation("default", 0);
            Property(p => p.PrivateKey).HasColumnName("SALT").HasMaxLength(128);
            Property(p => p.ModifiedDate).HasColumnName("UPDATE").HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed).IsRequired();//.HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.CheckCode).HasColumnName("CHECKHASH").HasMaxLength(256);

            HasIndex(ix => new { ix.UserId }).HasName("IX_CRYPTOGRAPHY_SGID").IsUnique(true).IsClustered(false);
            //HasMany(m => m.Members).WithMany(n => n.Roles);
        }
    }




}
