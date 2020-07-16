using Microsoft.Managed.Extensibility.EntityFramework;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.ComponentModel.Composition.Hosting;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    public class OAuthDbContext : ManagedDbContext
    {
        /// <summary>
        /// </summary>
        /// <param name="nameOrConnectionString"></param>
        public OAuthDbContext(string nameOrConnectionString)
            : base(nameOrConnectionString)
        {
            //解决团队开发中，多人迁移数据库造成的修改覆盖问题。
            Database.SetInitializer<OAuthDbContext>(null);
            //base.Configuration.AutoDetectChangesEnabled = false;
            ////关闭EF6.x 默认自动生成null判断语句
            //base.Configuration.UseDatabaseNullSemantics = true;           
        }

        public override void ComposeParts()
        {
            var catalog = new AggregateCatalog();
            catalog.Catalogs.Add(new DirectoryCatalog(AppDomain.CurrentDomain.SetupInformation.PrivateBinPath));
            var container = new CompositionContainer(catalog);
            container.ComposeParts(this);
        }
    }
}
