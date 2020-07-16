using Microsoft.Managed.Extensibility.EntityFramework;
using System;
using System.Data.Entity.ModelConfiguration;
using System.Data.Entity.ModelConfiguration.Configuration;


namespace Deveplex.Identity.EntityFramework.Configurations
{
    public class IdentityEntityConfiguration<TEntity, TKey> : EntityTypeConfiguration<TEntity>, IEntityConfigurationMapper
        where TEntity : class
        where TKey : IEquatable<TKey>
    {
        public virtual IMapperMetaData MapperMetaData { get; private set; }

        public virtual void Register(ConfigurationRegistrar configurations)
        {
            configurations.Add(this);
        }

    }
}
