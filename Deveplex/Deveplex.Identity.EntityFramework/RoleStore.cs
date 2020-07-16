using Microsoft.Identity;
using Microsoft.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Deveplex.Identity.EntityFramework
{
    public class RoleStore<TRole> : RoleStore<TRole, string>
        , IRoleStore<TRole>
        //, IQueryableRoleStore<TRole>
        where TRole : IdentityRole, new()
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="context"></param>
        public RoleStore(DbContext context)
            : base(context)
        {
        }
    }
}
