using Microsoft.AspNet.OAuth.Framework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace Microsoft.AspNet.OAuth.EntityFramework
{
    //public class OAuthStore<TApp> : OAuthStore<TApp, string>
    //   , IOAuthStore<TApp>
    //   where TApp : IdentityApp, new()
    //{
    //    private EntityStore<Client> _AppStore;
    //    private EntityStore<CryptographySecurity> _CryptoStore;
    //    private EntityStore<ClientScope> _AppScopeStore;
    //    private EntityStore<ClientInformation> _AppInfoStore;
    //    private EntityStore<Scopes> _ScopeStore;

    //    public OAuthStore()
    //        : this(new DbContext("DefaultConnection"))
    //    {
    //    }

    //    public OAuthStore(DbContext context)
    //        : base(context)
    //    {
    //        _AppStore = new EntityStore<Client>(context);
    //        _CryptoStore = new EntityStore<CryptographySecurity>(context);
    //        _AppInfoStore = new EntityStore<ClientInformation>(context);
    //        _AppScopeStore = new EntityStore<ClientScope>(context);
    //        _ScopeStore = new EntityStore<Scopes>(context);
    //    }
    //    /*
    //    public override async Task CreateAsync(TApp app)
    //    {
    //        ThrowIfDisposed();
    //        if (app == null)
    //        {
    //            throw new ArgumentNullException("app");
    //        }

    //        ////var r = EntityMapper.Map<TToken, Token>(token);

    //        //var t = _tokenStore.Add(app);
    //        //await SaveChangesAsync().WithCurrentCulture();
    //        await Task.FromResult(0);
    //    }

    //    public override async Task UpdateAsync(TApp app)
    //    {
    //        ThrowIfDisposed();
    //        if (app == null)
    //        {
    //            throw new ArgumentNullException("app");
    //        }

    //        //var r = EntityMapper.Map<TToken, Token>(token);

    //        //var t = _tokenStore.Update(token);
    //        //await SaveChangesAsync().WithCurrentCulture();
    //        await Task.FromResult(0);
    //    }

    //    public override async Task DeleteAsync(TApp app)
    //    {
    //        ThrowIfDisposed();
    //        if (app == null)
    //        {
    //            throw new ArgumentNullException("app");
    //        }

    //        ////var r = EntityMapper.Map<TToken, Token>(token);

    //        //var t = _tokenStore.Remove(token);
    //        //await SaveChangesAsync().WithCurrentCulture();
    //        await Task.FromResult(0);
    //    }
    //    */
    //    public override Task<TApp> FindAsync(string appId)
    //    {
    //        ThrowIfDisposed();
    //        return GetUserAggregateAsync(a => a.ClientId.Equals(appId));
    //    }

    //    //public override async Task<IList<TApp>> FindByUserIdAsync(string userId)
    //    //{
    //    //    ThrowIfDisposed();
    //    //    if (userId == null)
    //    //    {
    //    //        throw new ArgumentNullException("token");
    //    //    }

    //    //    var query = from a in _AppStore.Entities
    //    //                where a.UserId.Equals(userId)
    //    //                select a;
    //    //    var clients = await query.ToListAsync().WithCurrentCulture();
    //    //    return clients.Select(a => new TApp
    //    //    {
    //    //        AppId = a.ClientId,
    //    //        Name = a.Name,
    //    //        CallbackUrl = a.CallbackUrl,
    //    //        Description = a.Description,
    //    //        Status = (int)a.Status
    //    //    }).ToList();
    //    //}

    //    public override Task<string> GetSecretAsync(TApp app)
    //    {
    //        return base.GetSecretAsync(app);
    //    }

    //    public override async Task AddSecretAsync(TApp app, string secret)
    //    {
    //        ThrowIfDisposed();
    //        if (app == null)
    //        {
    //            throw new ArgumentNullException("app");
    //        }

    //        throw new NotImplementedException();
    //    }

    //    public override async Task SetSecretAsync(TApp app, string secret)
    //    {
    //        ThrowIfDisposed();
    //        if (app == null)
    //        {
    //            throw new ArgumentNullException("app");
    //        }

    //        throw new NotImplementedException();
    //    }

    //    public override async Task<bool> VerifySecretAsync(TApp app, string secret)
    //    {
    //        ThrowIfDisposed();
    //        if (app == null)
    //        {
    //            throw new ArgumentNullException("app");
    //        }

    //        var appId = app.AppId;
    //        var query = from a in _AppStore.Entities
    //                    where a.ClientId.Equals(appId) && a.Secret.Equals(secret, StringComparison.Ordinal)
    //                    select a;
    //        return await query.AnyAsync().WithCurrentCulture();
    //    }

    //    public override async Task<string> GetRedirectUriAsync(TApp app)
    //    {
    //        ThrowIfDisposed();
    //        if (app == null)
    //        {
    //            throw new ArgumentNullException("app");
    //        }

    //        var appId = app.AppId;
    //        var query = from a in _AppStore.Entities
    //                    where a.ClientId.Equals(appId)
    //                    select a.CallbackUrl;
    //        return await query.FirstOrDefaultAsync().WithCurrentCulture();
    //    }

    //    public override async Task SetRedirectUriAsync(TApp app, string url)
    //    {
    //        ThrowIfDisposed();
    //        if (app == null)
    //        {
    //            throw new ArgumentNullException("app");
    //        }

    //        throw new NotImplementedException();
    //    }

    //    public override async Task<IList<string>> GetScopeAsync(TApp app)
    //    {
    //        ThrowIfDisposed();
    //        if (app == null)
    //        {
    //            throw new ArgumentNullException("app");
    //        }

    //        var appId = app.AppId;
    //        var query = from s in _AppScopeStore.Entities
    //                    where s.ClientId.Equals(appId)
    //                    select s.Scope;
    //        return await query.ToListAsync().WithCurrentCulture();
    //    }

    //    public override Task AddScopeAsync(TApp app, string scope)
    //    {
    //        return base.AddScopeAsync(app, scope);
    //    }

    //    public override Task RemoveScopeAsync(TApp app, string scope)
    //    {
    //        return base.RemoveScopeAsync(app, scope);
    //    }

    //    public override Task<bool> IsInScopeAsync(TApp app, string scope)
    //    {
    //        return base.IsInScopeAsync(app, scope);
    //    }

    //    public override Task<bool> HasSecretAsync(TApp app)
    //    {
    //        return base.HasSecretAsync(app);
    //    }

    //    ////////////////////////////////////////////////////////////////////////////////////////////////

    //    private bool AreScopesLoaded(TApp app)
    //    {
    //        return _AppScopeStore.IsLoaded;
    //    }

    //    private async Task EnsureScopesLoaded(TApp app)
    //    {
    //        if (!AreScopesLoaded(app))
    //        {
    //            var appId = app.AppId;
    //            var query = from a in _AppScopeStore.Entities
    //                        where a.ClientId.Equals(appId)
    //                        select a;
    //            await query.LoadAsync().WithCurrentCulture();
    //            query.ToList().ForEach(s =>
    //            {
    //                app.Scopes.Add(new IdentityScope<string>
    //                {
    //                    Scope = s.Scope
    //                });
    //            });
    //            _AppScopeStore.IsLoaded = true;
    //        }
    //    }

    //    protected async Task<TApp> GetUserAggregateAsync(Expression<Func<Client, bool>> filter)
    //    {
    //        TApp app = null;
    //        var client = await _AppStore.Entities.SingleOrDefaultAsync(filter);
    //        if (client != null)
    //        {
    //            app = new TApp
    //            {
    //                AppId = client.ClientId,
    //                Name = client.Name,
    //                CallbackUrl = client.CallbackUrl,
    //                Description = client.Description,
    //                Status = (int)client.Status
    //            };
    //        }
    //        if (app != null)
    //        {
    //            await EnsureScopesLoaded(app).WithCurrentCulture();
    //            //var r = EntityMapper.Map<Token, TToken>(token);
    //        }
    //        return app;
    //    }

    //    ////////////////////////////////////////////////////////////////////////////////////////////////////////

    //    /// <summary>
    //    ///     If disposing, calls dispose on the Context.  Always nulls out the Context
    //    /// </summary>
    //    /// <param name="disposing"></param>
    //    protected override void Dispose(bool disposing)
    //    {
    //        base.Dispose(disposing);
    //        _AppStore = null;
    //        _CryptoStore = null;
    //        _AppInfoStore = null;
    //        _AppScopeStore = null;
    //        _ScopeStore = null;
    //    }
    //}

    public class OAuthStore<TApp, TKey, TScope, TClientScope> : OAuthStore<TApp, TKey, TScope, TClientScope>
        , IOAuthRedirectUriStore<TApp, TKey>
        , IUserSecurityStampStore<TApp, TKey>
        , IUserLockoutStore<TApp, TKey>
        , IOAuthStore<TApp, TKey>
        where TApp : Client<TKey>, new()
        where TScope : Scope<TKey>
        where TClientScope : ClientScope<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        public OAuthStore()
            : this(new DbContext("DefaultConnection"))
        {
            DisposeContext = true;
        }

        public OAuthStore(DbContext context)
            : base(context)
        {
        }

        public virtual Task<string> GetRedirectUriAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public virtual Task SetRedirectUriAsync(TApp app, string url)
        {
            throw new NotImplementedException();
        }

        public virtual Task<IList<string>> GetScopeAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public virtual Task AddScopeAsync(TApp app, string scope)
        {
            throw new NotImplementedException();
        }

        public virtual Task<bool> IsInScopeAsync(TApp app, string scope)
        {
            throw new NotImplementedException();
        }

        public virtual Task RemoveScopeAsync(TApp app, string scope)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetSecurityStampAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public Task SetSecurityStampAsync(TApp app, string stamp)
        {
            throw new NotImplementedException();
        }

        public Task<int> GetAccessFailedCountAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetLockoutEnabledAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public Task<DateTimeOffset> GetLockoutEndDateAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public Task<int> IncrementAccessFailedCountAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public Task ResetAccessFailedCountAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public Task SetLockoutEnabledAsync(TApp app, bool enabled)
        {
            throw new NotImplementedException();
        }

        public Task SetLockoutEndDateAsync(TApp app, DateTimeOffset lockoutEnd)
        {
            throw new NotImplementedException();
        }
    }

    public class OAuthStore<TApp, TKey, TScope, TClientScope>
        : IOAuthSecretStore<TApp, TKey>
        , IOAuthScopeStore<TApp, TKey>
        , ITransactionStore<TApp, TKey>
        , IOAuthStore<TApp, TKey>
        where TApp : Client<TKey, TClientScope>
        where TScope : Scope<TKey>
        where TClientScope : ClientScope<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        //private readonly EntityStore<Client> _appStore;
        //private readonly EntityStore<ClientInformation> _appinfoStore;

        private bool _disposed;

        protected bool DisposeContext { get; set; }

        protected bool AutoSaveChanges { get; set; }


        public OAuthStore(DbContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            Context = context;
            AutoSaveChanges = true;

            //_appStore = new EntityStore<Client>(context);
            //_appinfoStore = new EntityStore<ClientInformation>(context);
        }

        protected DbContext Context { get; private set; }

        public virtual Task<TApp> FindAsync(string appId)
        {
            throw new NotImplementedException();
        }

        //public virtual Task CreateAsync(TApp app)
        //{
        //    throw new NotImplementedException();
        //}

        //public virtual Task UpdateAsync(TApp app)
        //{
        //    throw new NotImplementedException();
        //}

        //public virtual Task DeleteAsync(TApp app)
        //{
        //    throw new NotImplementedException();
        //}

        public virtual Task<string> GetSecretAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public virtual Task AddSecretAsync(TApp app, string secret)
        {
            throw new NotImplementedException();
        }

        public virtual Task SetSecretAsync(TApp app, string secret)
        {
            throw new NotImplementedException();
        }

        public virtual Task<bool> VerifySecretAsync(TApp app, string secret)
        {
            throw new NotImplementedException();
        }

        public virtual Task<bool> HasSecretAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public virtual Task AddSecurityPasswordAsync(TApp app, string password, string PrivateKey)
        {
            throw new NotImplementedException();
        }

        public virtual Task SetSecurityPasswordAsync(TApp app, string password, string PrivateKey)
        {
            throw new NotImplementedException();
        }

        public virtual Task<bool> VerifySecurityPasswordAsync(TApp app, string password)
        {
            throw new NotImplementedException();
        }

        public virtual Task SetCryptographySecurityAsync(TApp app, SecurityInfo info)
        {
            throw new NotImplementedException();
        }

        public virtual Task<SecurityInfo> GetCryptographySecurityAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public virtual Task<string> GetPrivateKeyAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        // Only call save changes if AutoSaveChanges is true
        public virtual async Task CommitChangesAsync()
        {
            if (AutoSaveChanges)
            {
                await Context.SaveChangesAsync().WithCurrentCulture();
            }
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
            if (DisposeContext && disposing && Context != null)
            {
                Context.Dispose();
            }
            _disposed = true;
            Context = null;
        }

        /// <summary>
        ///     Dispose the store
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public Task AddScopeAsync(TApp app, string scope)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<KeyValuePair<TKey, string>>> GetScopeAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public Task<bool> IsInScopeAsync(TApp app, string scope)
        {
            throw new NotImplementedException();
        }

        public Task RemoveScopeAsync(TApp app, string scope)
        {
            throw new NotImplementedException();
        }

        public Task CreateAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public Task UpdateAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public Task DeleteAsync(TApp app)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetHashKeyAsync(TApp user)
        {
            throw new NotImplementedException();
        }
    }
}
