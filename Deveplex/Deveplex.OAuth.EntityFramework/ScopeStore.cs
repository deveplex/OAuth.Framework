using Microsoft.Identity;
using Microsoft.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Deveplex.OAuth.EntityFramework
{
    public class ScopeStore<TScope> : RoleStore<TScope, string>
        , IRoleStore<TScope>
        //, IQueryableRoleStore<TRole>
        where TScope : Scope, new()
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="context"></param>
        public ScopeStore(DbContext context)
            : base(context)
        {
        }
    }
}
