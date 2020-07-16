using Microsoft.Managed.Extensibility.EntityFramework;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition.Hosting;
using System.Data.Entity;

namespace Micosoft.AspNet.Identity.Migrations
{
    class IdentityMigrationsDbContext : ManagedDbContext
    {
        public IdentityMigrationsDbContext() : base("test_identity") { }

        //public override void ComposeParts()
        //{
        //    var catalog = new AggregateCatalog();
        //    catalog.Catalogs.Add(new DirectoryCatalog(AppDomain.CurrentDomain.BaseDirectory));
        //    //catalog.Catalogs.Add(new DirectoryCatalog(AppDomain.CurrentDomain.SetupInformation.PrivateBinPath));
        //    //catalog.Catalogs.Add(new AssemblyCatalog(Assembly.GetExecutingAssembly()));
        //    CompositionContainer = new CompositionContainer(catalog);
        //    //container.ComposeParts(this);

        //}
    }
}
