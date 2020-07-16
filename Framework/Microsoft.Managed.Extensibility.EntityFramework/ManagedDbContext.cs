using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.ComponentModel.Composition.Hosting;
using System.ComponentModel.Composition.Primitives;
using System.Data.Common;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Data.Entity.ModelConfiguration.Conventions;
using System.Linq;
using System.Reflection;

namespace Microsoft.Managed.Extensibility.EntityFramework
{
    [Export(typeof(DbContext))]
    public class ManagedDbContext : DbContext
    {
        public ManagedDbContext()
            : this("DefaultConnection")
        {
        }

        /// <summary>
        /// </summary>
        /// <param name="nameOrConnectionString"></param>
        public ManagedDbContext(string nameOrConnectionString)
            : base(nameOrConnectionString)
        {
            ComposeParts();
        }

        /// <summary>
        /// </summary>
        /// <param name="existingConnection">An existing connection to use for the new context.</param>
        /// <param name="model">The model that will back this context.</param>
        /// <param name="contextOwnsConnection">
        ///     Constructs a new context instance using the existing connection to connect to a
        ///     database, and initializes it from the given model.  The connection will not be disposed when the context is
        ///     disposed if contextOwnsConnection is false.
        /// </param>
        public ManagedDbContext(DbConnection existingConnection, DbCompiledModel model, bool contextOwnsConnection)
            : base(existingConnection, model, contextOwnsConnection)
        {
            ComposeParts();
        }

        /// <summary>
        /// </summary>
        /// <param name="model">The model that will back this context.</param>
        public ManagedDbContext(DbCompiledModel model)
            : base(model)
        {
            ComposeParts();
        }

        /// <summary>

        /// </summary>
        /// <param name="existingConnection">An existing connection to use for the new context.</param>
        /// <param name="contextOwnsConnection">If set to true the connection is disposed when the context is disposed, otherwise
        ///     the caller must dispose the connection.
        /// </param>
        public ManagedDbContext(DbConnection existingConnection, bool contextOwnsConnection)
            : base(existingConnection, contextOwnsConnection)
        {
            ComposeParts();
        }

        /// <summary>
        /// </summary>
        /// <param name="nameOrConnectionString">Either the database name or a connection string.</param>
        /// <param name="model">The model that will back this context.</param>
        public ManagedDbContext(string nameOrConnectionString, DbCompiledModel model)
            : base(nameOrConnectionString, model)
        {
            ComposeParts();
        }

        [ImportMany]
        private IEnumerable<IEntityConfigurationMapper> EntityConfigurationMappers { get; set; }


        public virtual void ComposeParts()
        {
            try
            {
                var catalog = new AggregateCatalog();
                catalog.Catalogs.Add(new DirectoryCatalog(AppDomain.CurrentDomain.BaseDirectory));
                //catalog.Catalogs.Add(new DirectoryCatalog(AppDomain.CurrentDomain.SetupInformation.PrivateBinPath));
                //catalog.Catalogs.Add(new AssemblyCatalog(Assembly.GetExecutingAssembly()));
                var container = new CompositionContainer(catalog);
                container.ComposeParts(this);
            }
            catch (ReflectionTypeLoadException ex)
            {
                foreach (var e in ex.LoaderExceptions)
                    throw e;
            }
        }

        protected virtual IEnumerable<IEntityConfigurationMapper> FilterEntityConfigurationMappers(IEnumerable<IEntityConfigurationMapper> mappers)
        {
            return mappers;
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            if (modelBuilder == null)
            {
                throw new ArgumentNullException("modelBuilder");
            }

            //表名不用复数形式
            modelBuilder.Conventions.Remove<PluralizingTableNameConvention>();
            //移除一对多的级联删除约定，想要级联删除可以在 EntityTypeConfiguration<TEntity>的实现类中进行控制 
            modelBuilder.Conventions.Remove<OneToManyCascadeDeleteConvention>();
            //多对多启用级联删除约定，不想级联删除可以在删除前判断关联的数据进行拦截  
            modelBuilder.Conventions.Remove<ManyToManyCascadeDeleteConvention>();

            //try
            //{
            //    //if (EntityConfigurationMappers == null || EntityConfigurationMappers.Count() <= 0)
            //    //{
            //    EntityConfigurationMappers = CompositionContainer.GetExportedValues<IEntityConfigurationMapper>();
            //    //}
            //}
            //catch(ReflectionTypeLoadException ex)
            //{
            //    foreach (var e in ex.LoaderExceptions)
            //    throw e;
            //}
            var configurationMappers = FilterEntityConfigurationMappers(EntityConfigurationMappers);
            if (configurationMappers != null)
            {
                foreach (var mapper in configurationMappers)
                {
                    mapper.Register(modelBuilder.Configurations);
                }
            }

            base.OnModelCreating(modelBuilder);
        }
    }
}
