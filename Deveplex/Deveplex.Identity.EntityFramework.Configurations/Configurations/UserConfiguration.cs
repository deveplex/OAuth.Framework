using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Identity.EntityFramework.Configurations
{
    public class UserConfiguration : IdentityEntityConfiguration<IdentityUser, string>
    {
        public UserConfiguration()
        {
            ToTable("Users");
            HasKey(k => k.Id);//.HasName("PK_USERS")

            Property(p => p.Id).HasColumnName("ID").HasMaxLength(256).IsRequired();//.HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);//.HasColumnAnnotation("default", "REPLACE(LTRIM(RTRIM(NEWID())),'-','')");
            Property(p => p.IsDeleted).HasColumnName("ISDEL").IsRequired();//.HasColumnAnnotation("default", 0);

            Property(p => p.UserCode).HasColumnName("SAID").HasMaxLength(256);
            Property(p => p.UserName).HasColumnName("USERNAME").HasMaxLength(256).IsRequired();
            Property(p => p.Email).HasColumnName("EMAIL").HasMaxLength(256);
            Property(p => p.EmailConfirmed).HasColumnName("ISVEMAIL").IsRequired();//.HasColumnAnnotation("default", 0);
            Property(p => p.PasswordHash).HasColumnName("PWDHASH").HasMaxLength(2046);
            Property(p => p.SecurityStamp).HasColumnName("SECSTAMP").HasMaxLength(256);
            Property(p => p.PhoneNumber).HasColumnName("MOBILE").HasMaxLength(256);
            Property(p => p.PhoneNumberConfirmed).HasColumnName("ISVMOBILE").IsRequired();//.HasColumnAnnotation("default", 0);
            Property(p => p.TwoFactorEnabled).HasColumnName("ISTWOFCTR").IsRequired();//.HasColumnAnnotation("default", 0);
            Property(p => p.LockoutEndDate).HasColumnName("UNLOCKDATE").IsOptional();
            Property(p => p.LockoutEnabled).HasColumnName("ISLOCKED").IsRequired();//.HasColumnAnnotation("default", 0);
            Property(p => p.AccessFailedCount).HasColumnName("FAILEDCNT").IsRequired();//.HasColumnAnnotation("default", 0);
            Property(p => p.Status).HasColumnName("STATUS").HasColumnType("int").IsRequired();
            Property(p => p.CreatedDate).HasColumnName("CRDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);//.HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.ModifiedDate).HasColumnName("UPDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed);//.HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.CheckCode).HasColumnName("CHECKHASH").HasMaxLength(256);

            HasIndex(ix=>new { ix.UserCode }).HasName("IX_USERS_SAID").IsUnique(true).IsClustered(false);
            HasIndex(ix => new { ix.UserName }).HasName("IX_USERS_USERNAME").IsUnique(true).IsClustered(false);
            //HasIndex(ix => new { ix.Email }).HasName("IX_USERS_EMAIL").IsUnique(true).IsClustered(false);
            //HasIndex(ix => new { ix.PhoneNumber }).HasName("IX_USERS_MOBILE").IsUnique(true).IsClustered(false);

            //HasMany(u => u.Claims).WithOptional().HasForeignKey(uc => uc.UserId);
            //HasMany(u => u.Roles).WithOptional().HasForeignKey(ur => ur.UserId);
            //HasMany(u => u.Logins).WithOptional().HasForeignKey(ul => ul.UserId);
            //HasMany(m => m.Members).WithMany(n => n.Roles);
        }
    }




}
