using Microsoft.Managed.Extensibility.EntityFramework;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.ComponentModel.Composition.Hosting;
using System.Data.Entity;

namespace Micosoft.AspNet.Identity.Migrations
{
    /**
     * SqlLocalDB stop
     * SqlLocalDB delete
     * SqlLocalDB start
     **/

    /**
     * Enable-Migrations -EnableAutomaticMigrations -Force
     * Add-Migration InitialCreate
     * Update-Database -Verbose
     **/

    class IdentityMigrationsDbContext : ManagedDbContext
    {
        public IdentityMigrationsDbContext() 
            : base("test_authentication")
        {
        }

        public override void ComposeParts()
        {
            var catalog = new AggregateCatalog();
            catalog.Catalogs.Add(new DirectoryCatalog(AppDomain.CurrentDomain.BaseDirectory));
            //catalog.Catalogs.Add(new DirectoryCatalog(AppDomain.CurrentDomain.SetupInformation.PrivateBinPath));
            //catalog.Catalogs.Add(new AssemblyCatalog(Assembly.GetExecutingAssembly()));
            var container = new CompositionContainer(catalog);
            container.ComposeParts(this);
        }
    }
}
