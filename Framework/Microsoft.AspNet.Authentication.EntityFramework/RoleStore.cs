using System;
using System.Data.Entity;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity.EntityFramework
{
    public class RoleStore<TRole> : RoleStore<TRole, string>
        , IRoleStore<TRole>
        //, IQueryableRoleStore<TRole>
        where TRole : IdentityRole, new()
    {
        public RoleStore()
            : base(new DbContext("DefaultConnection"))
        {
            DisposeContext = true;
        }

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="context"></param>
        public RoleStore(DbContext context)
            : base(context)
        {
        }
    }

    public class RoleStore<TRole, TKey>
        : IRoleStore<TRole, TKey>
        //, IQueryableRoleStore<TRole, TKey>
        , IDisposable
        where TRole : IdentityRole<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        private readonly EntityStore<TRole> _roleStore;

        private bool _disposed;

        public RoleStore(DbContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            Context = context;
            _roleStore = new EntityStore<TRole>(context);
            //_logins = Context.Set<TUserLogin>();
            //_userClaims = Context.Set<TUserClaim>();
            //_userRoles = Context.Set<TUserRole>();
        }

        /// <summary>
        ///     Context for the store
        /// </summary>
        public DbContext Context { get; private set; }

        /// <summary>
        ///     If true will call dispose on the DbContext during Dipose
        /// </summary>
        public bool DisposeContext { get; set; }


        public Task CreateAsync(TRole role)
        {
            throw new NotImplementedException();
        }

        public Task DeleteAsync(TRole role)
        {
            throw new NotImplementedException();
        }

        public Task<TRole> FindByIdAsync(TKey roleId)
        {
            throw new NotImplementedException();
        }

        public Task<TRole> FindByNameAsync(string roleName)
        {
            throw new NotImplementedException();
        }

        public Task UpdateAsync(TRole role)
        {
            throw new NotImplementedException();
        }

        protected void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        /// <summary>
        ///     If disposing, calls dispose on the Context.  Always nulls out the Context
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            _disposed = true;
        }

        /// <summary>
        ///     Dispose the store
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
