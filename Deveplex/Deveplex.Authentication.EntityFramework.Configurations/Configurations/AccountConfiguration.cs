using Deveplex.Authentication.Entity;
using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Authentication.EntityFramework.Configurations
{
    public class AccountConfiguration : AuthenticationEntityConfiguration<Account,string>
    {
        public AccountConfiguration()
        {
            ToTable("accounts");
            HasKey(k => k.Id);//.HasName("PK_ACCOUNTS")

            Property(p => p.Id).HasColumnName("ID").HasDatabaseGeneratedOption(DatabaseGeneratedOption.Identity);
            Property(p => p.IsDeleted).HasColumnName("ISDEL").IsRequired().HasColumnAnnotation("default", 0);

            Property(p => p.AccountId).HasColumnName("SGID").HasMaxLength(256).IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Identity);//.HasColumnAnnotation("default", "REPLACE(LTRIM(RTRIM(NEWID())),'-','')");
            Property(p => p.UserId).HasColumnName("SUID").HasMaxLength(256).IsRequired();//.HasColumnAnnotation("default", "REPLACE(LTRIM(RTRIM(STR(RAND(ABS(CHECKSUM(NEWID())))*9+1,20,20))),'.','')");
            Property(p => p.UserName).HasColumnName("USERNAME").HasMaxLength(128).IsRequired();
            Property(p => p.EmailConfirmed).HasColumnName("ISVEMAIL").IsRequired().HasColumnAnnotation("default", 0);
            Property(p => p.PasswordHash).HasColumnName("PWDHASH").HasMaxLength(1024);
            Property(p => p.SecurityStamp).HasColumnName("SECSTAMP").HasMaxLength(256);
            Property(p => p.PhoneNumberConfirmed).HasColumnName("ISVMOBILE").IsRequired().HasColumnAnnotation("default", 0);
            Property(p => p.TwoFactorEnabled).HasColumnName("ISTWOFACTOR").IsRequired().HasColumnAnnotation("default", 0);
            Property(p => p.LockoutEndDateUtc).HasColumnName("UNLOCKDATE").IsOptional();
            Property(p => p.LockoutEnabled).HasColumnName("ISLOCKED").IsRequired().HasColumnAnnotation("default", 0);
            Property(p => p.AccessFailedCount).HasColumnName("FAILEDCOUNT").IsRequired().HasColumnAnnotation("default", 0);
            Property(p => p.Status).HasColumnName("STATUS").HasColumnType("int").IsRequired().HasColumnAnnotation("default", 0);
            Property(p => p.CreatedDate).HasColumnName("CRDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Identity).HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.ModifiedDate).HasColumnName("UPDATE").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Computed).HasColumnAnnotation("default", "GETUTCDATE()");
            Property(p => p.CheckCode).HasColumnName("HASHKEY").HasMaxLength(256);

            HasIndex(ix => new { ix.AccountId }).HasName("IX_ACCOUNTS_SGID").IsUnique(true).IsClustered(false);
            HasIndex(ix => new { ix.UserId }).HasName("IX_ACCOUNTS_SUID").IsUnique(true).IsClustered(false);
            HasIndex(ix => new { ix.UserName }).HasName("IX_ACCOUNTS_USERNAME").IsUnique(true).IsClustered(false);
            //HasMany(m => m.Members).WithMany(n => n.Roles);
        }
    }




}
