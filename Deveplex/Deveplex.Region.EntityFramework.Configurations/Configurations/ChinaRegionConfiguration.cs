using Deveplex.Region.Entity;
using System;
using System.ComponentModel.DataAnnotations.Schema;

namespace Deveplex.Region.EntityFramework.Configurations
{
    public class ChinaRegionConfiguration : NationalRegionEntityConfiguration<NationalRegion, string>
    {
        public ChinaRegionConfiguration()
        {
            ToTable("86");
            HasKey(k => k.Id);

            Property(p => p.Id).HasColumnName("ID").IsRequired().HasDatabaseGeneratedOption(DatabaseGeneratedOption.Identity);
            Property(p => p.IsDeleted).HasColumnName("ISDEL").IsRequired().HasColumnAnnotation("default", 0);

            Property(p => p.Code).HasColumnName("CODE").IsRequired();
            Property(p => p.ParentCode).HasColumnName("PCODE");
            Property(p => p.ShortName).HasColumnName("SNAME").HasMaxLength(128);
            Property(p => p.Name).HasColumnName("NAME").HasMaxLength(256).IsRequired();
            Property(p => p.FullName).HasColumnName("FNAME").HasMaxLength(512);
            Property(p => p.InternationalName).HasColumnName("MNAME").HasMaxLength(256);
            Property(p => p.Level).HasColumnName("LEVEL").IsRequired();
            Property(p => p.ZoneCode).HasColumnName("ZONE");
            Property(p => p.PostalCode).HasColumnName("ZIP");
            Property(p => p.Longitude).HasColumnName("LNG");
            Property(p => p.Latitude).HasColumnName("LAT");

            HasIndex(ix => new { ix.Code }).HasName("IX_NATIONALREGION_CODE").IsUnique(true).IsClustered(false);
            //HasMany(m => m.Members).WithMany(n => n.Roles);
        }
    }
}
