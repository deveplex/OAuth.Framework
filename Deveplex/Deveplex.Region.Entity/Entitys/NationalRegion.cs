using Deveplex.Entity;
using System;
using System.ComponentModel.DataAnnotations;

namespace Deveplex.Region.Entity
{
    public class NationalRegion : NationalRegion<int>, IEntity
    {
    }

    public class NationalRegion<TKey> : IEntity<TKey>, IIdentity<string>
        where TKey : IEquatable<TKey>
    {
        public string Id { get; set; }

        public int Code { get; set; }

        public int? ParentCode { get; set; }

        public string ShortName { get; set; }

        [Required]
        public string Name { get; set; }

        public string FullName { get; set; }

        public string InternationalName { get; set; }

        public int Level { get; set; }

        public int? ZoneCode { get; set; }

        public int? PostalCode { get; set; }

        public double? Longitude { get; set; }

        public double? Latitude { get; set; }

        public bool IsDeleted { get; set; }
    }
}
