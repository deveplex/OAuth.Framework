using Microsoft.AspNet.OAuth;
using Microsoft.AspNet.OAuth.Framework;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    public class OAuthManager<TApp> : OAuthManager<TApp, string>
        where TApp : class, IClient<string>
    {
        public OAuthManager(IOAuthStore<TApp> store)
            : base(store)
        {
        }
    }

    public class OAuthManager<TApp, TKey> : IDisposable
        where TApp : class, IClient<TKey>
        where TKey : IEquatable<TKey>
    {
        private bool _disposed;
        private TimeSpan _defaultLockout = TimeSpan.Zero;
        private IPasswordHasher _passwordHasher;
        private IIdentityValidator<string> _passwordValidator;
        private IIdentityValidator<TApp> _userValidator;

        public OAuthManager(IOAuthStore<TApp, TKey> store)
        {
            if (store == null)
            {
                throw new ArgumentNullException("store");
            }

            Store = store;
            ClientValidator = new ClientValidator<TApp, TKey>(this);
            SecretValidator = new PasswordValidator();
            PasswordHasher = new PasswordHasher();
        }

        protected internal IOAuthStore<TApp, TKey> Store { get; }

        /// <summary>
        ///     Used to hash/verify passwords
        /// </summary>
        public IPasswordHasher PasswordHasher
        {
            get
            {
                ThrowIfDisposed();
                return _passwordHasher;
            }
            set
            {
                ThrowIfDisposed();
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }
                _passwordHasher = value;
            }
        }

        /// <summary>
        ///     Used to validate users before changes are saved
        /// </summary>
        public IIdentityValidator<TApp> ClientValidator
        {
            get
            {
                ThrowIfDisposed();
                return _userValidator;
            }
            set
            {
                ThrowIfDisposed();
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }
                _userValidator = value;
            }
        }

        /// <summary>
        ///     Used to validate passwords before persisting changes
        /// </summary>
        public IIdentityValidator<string> SecretValidator
        {
            get
            {
                ThrowIfDisposed();
                return _passwordValidator;
            }
            set
            {
                ThrowIfDisposed();
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }
                _passwordValidator = value;
            }
        }

        /// <summary>
        ///     Returns true if the store is an IOAuthRedirectUriStore
        /// </summary>
        public virtual bool SupportsOAuthRedirectUri
        {
            get
            {
                ThrowIfDisposed();
                return Store is IOAuthRedirectUriStore<TApp, TKey>;
            }
        }

        /// <summary>
        ///     Returns true if the store is an IOAuthSecretStore
        /// </summary>
        public virtual bool SupportsOAuthSecret
        {
            get
            {
                ThrowIfDisposed();
                return Store is IOAuthSecretStore<TApp, TKey>;
            }
        }

        /// <summary>
        ///     Returns true if the store is an IOAuthScopeStore
        /// </summary>
        public virtual bool SupportsOAuthScope
        {
            get
            {
                ThrowIfDisposed();
                return Store is IOAuthScopeStore<TApp, TKey>;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="Id"></param>
        /// <returns></returns>
        public virtual async Task<IList<TApp>> FindByIdAsync(TKey Id)
        {
            ThrowIfDisposed();
            return await Store.FindByIdAsync(Id).WithCurrentCulture();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="appId"></param>
        /// <returns></returns>
        public virtual async Task<TApp> FindAsync(string appId)
        {
            ThrowIfDisposed();
            return await Store.FindAsync(appId).WithCurrentCulture();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        //public virtual async Task<IList<TApp>> FindByUserIdAsync(TKey userId)
        //{
        //    ThrowIfDisposed();
        //    return await Store.FindByUserIdAsync(userId).WithCurrentCulture();
        //}

        /// <summary>
        /// 
        /// </summary>
        /// <param name="appId"></param>
        /// <param name="secret"></param>
        /// <returns></returns>
        public virtual async Task<TApp> FindAsync(string appId, string secret)
        {
            ThrowIfDisposed();
            var secretStore = GetSecretStore();
            var app = await FindAsync(appId).WithCurrentCulture();
            if (app == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("AppIdNotFound"), appId));
            }
            return await CheckSecretAsync(app, secret).WithCurrentCulture() ? app : null;
        }

        public virtual async Task<string> GetSecretAsync(string appId)
        {
            ThrowIfDisposed();
            var secretStore = GetSecretStore();
            var app = await FindAsync(appId);
            if (app == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("AppIdNotFound"), appId));
            }
            return await secretStore.GetSecretAsync(app).WithCurrentCulture();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="appId"></param>
        /// <param name="secret"></param>
        /// <returns></returns>
        public virtual async Task<OperationResult> AddSecretAsync(string appId, string secret)
        {
            ThrowIfDisposed();
            var secretStore = GetSecretStore();
            var app = await FindAsync(appId);
            if (app == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("AppIdNotFound"), appId));
            }
            if (await secretStore.HasSecretAsync(app).WithCurrentCulture())
            {
                return OperationResult.Failed(R.String.Get("ClientAlreadyHasSecret"));
            }
            var result = await CreatePasswordAsync(secretStore, app, secret).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return OperationResult.Success;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="appId"></param>
        /// <param name="secret"></param>
        /// <returns></returns>
        public virtual async Task<OperationResult> ResetSecretAsync(string appId, string secret)
        {
            ThrowIfDisposed();
            var secretStore = GetSecretStore();
            var app = await FindAsync(appId);
            if (app == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("AppIdNotFound"), appId));
            }
            if (!await secretStore.HasSecretAsync(app).WithCurrentCulture())
            {
                return OperationResult.Failed(R.String.Get("ClientNotHasSecret"));
            }
            var result = await UpdatePasswordAsync(secretStore, app, secret).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return OperationResult.Success;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="app"></param>
        /// <param name="secret"></param>
        /// <returns></returns>
        public virtual async Task<bool> CheckSecretAsync(TApp app, string secret)
        {
            ThrowIfDisposed();
            if (app == null)
            {
                return false;
            }

            var secretStore = GetSecretStore();
            return await VerifyPasswordAsync(secretStore, app, secret).WithCurrentCulture();
        }

        public virtual async Task<OperationResult> RemoveSecretAsync(string appId)
        {
            ThrowIfDisposed();
            var secretStore = GetSecretStore();
            var app = await FindAsync(appId);
            if (app == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("AppIdNotFound"), appId));
            }
            if (await secretStore.HasSecretAsync(app).WithCurrentCulture())
            {
                return OperationResult.Success;
            }
            var result = await RemovePasswordAsync(secretStore, app).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return OperationResult.Success;
        }

        public virtual async Task<bool> HasSecretAsync(string appId)
        {
            ThrowIfDisposed();
            var secretStore = GetSecretStore();
            var app = await FindAsync(appId);
            if (app == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("AppIdNotFound"), appId));
            }
            return await secretStore.HasSecretAsync(app).WithCurrentCulture();
        }

        public virtual async Task<string> GetRedirectUriAsync(string appId)
        {
            ThrowIfDisposed();
            var redirectUriStore = GetRedirectUriStore();
            var app = await FindAsync(appId);
            if (app == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("AppIdNotFound"), appId));
            }
            return await redirectUriStore.GetRedirectUriAsync(app).WithCurrentCulture();
        }

        public virtual async Task<OperationResult> SetRedirectUriAsync(string appId, string url)
        {
            ThrowIfDisposed();
            var redirectUriStore = GetRedirectUriStore();
            var app = await FindAsync(appId);
            if (app == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("AppIdNotFound"), appId));
            }
            await redirectUriStore.SetRedirectUriAsync(app, url).WithCurrentCulture();
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return OperationResult.Success;
        }

        public virtual async Task<IList<string>> GetScopeAsync(string appId)
        {
            ThrowIfDisposed();
            var scopeStore = GetScopeStore();
            var app = await FindAsync(appId);
            if (app == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("AppIdNotFound"), appId));
            }
            return await scopeStore.GetScopeAsync(app).WithCurrentCulture();
        }

        public virtual async Task<OperationResult> AddScopeAsync(string appId, string scope)
        {
            ThrowIfDisposed();
            var scopeStore = GetScopeStore();
            var app = await FindAsync(appId);
            if (app == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("AppIdNotFound"), appId));
            }
            await scopeStore.AddScopeAsync(app, scope).WithCurrentCulture();
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return OperationResult.Success;
        }

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        /// <summary>
        /// 
        /// </summary>
        /// <param name="store"></param>
        /// <param name="user"></param>
        /// <param name="secret"></param>
        /// <returns></returns>
        internal async Task<OperationResult> CreatePasswordAsync(IOAuthSecretStore<TApp, TKey> store, TApp app, string password)
        {
            var result = await PasswordValidator.ValidateAsync(password).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            if (SupportsUserSecurityStamp)
            {
                var securityStampStore = GetSecurityStampStore();
                await securityStampStore.SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
            }
            var srcHash = PasswordHasher.HashPassword(password);
            var destHash = srcHash;
            string salt;
            var passwordHash = Framework.Crypto.Encrypt(destHash, out salt);
            await store.AddPasswordHashAsync(user, passwordHash, salt).WithCurrentCulture();
            return OperationResult.Success;
        }

        internal async Task<OperationResult> UpdatePasswordAsync(IOAuthSecretStore<TApp, TKey> store, TApp app, string password)
        {
            var passwordHash = PasswordHasher.HashPassword(password);
            //if (SupportsCryptographySecurity)
            {
                //var cryptographyStore = GetCryptographySecurityStore();
                string salt;
                var hash = Crypto.Encrypt(passwordHash, out salt);
                await store.SetPasswordAsync(app, hash, salt);
                await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            }
            await store.SetSecretAsync(app, passwordHash).WithCurrentCulture();
            return OperationResult.Success;
        }

        internal async Task<OperationResult> RemovePasswordAsync(IOAuthSecretStore<TApp, TKey> store, TApp app)
        {
            await store.SetSecretAsync(app, null).WithCurrentCulture();
            //if (SupportsCryptographySecurity)
            {
                //var cryptographyStore = GetCryptographySecurityStore();
                await store.SetPasswordAsync(app, null, null).WithCurrentCulture();
            }
            return OperationResult.Success;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="store"></param>
        /// <param name="app"></param>
        /// <param name="secret"></param>
        /// <returns></returns>
        internal virtual async Task<bool> VerifyPasswordAsync(IOAuthSecretStore<TApp, TKey> store, TApp app, string password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return false;
            }
            if (!await store.HasSecretAsync(app).WithCurrentCulture())
            {
                return false;
            }
            var passwordHash = password;// CryptographyHasher.HashPassword(password);
            //if (SupportsCryptographySecurity)
            {
                //var cryptographyStore = GetCryptographySecurityStore();
                var salt = await cryptographyStore.GetPrivateKeyAsync(app);
                var hash = Crypto.Encrypt(passwordHash, salt);
                return await Store.VerifyPasswordAsync(app, hash);
            }
            //else
            //{
            //    return await store.VerifySecretAsync(app, passwordHash);
            //}
        }

        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        // IOAuthRedirectUriStore methods
        private IOAuthRedirectUriStore<TApp, TKey> GetRedirectUriStore()
        {
            var cast = Store as IOAuthRedirectUriStore<TApp, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException("Store Not IOAuthRedirectUriStore");
            }
            return cast;
        }

        // IOAuthSecretStore methods
        private IOAuthSecretStore<TApp, TKey> GetSecretStore()
        {
            var cast = Store as IOAuthSecretStore<TApp, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException("Store Not IOAuthSecretStore");
            }
            return cast;
        }

        // IOAuthScopeStore methods
        private IOAuthScopeStore<TApp, TKey> GetScopeStore()
        {
            var cast = Store as IOAuthScopeStore<TApp, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException("Store Not IOAuthScopeStore");
            }
            return cast;
        }

        // ITransactionStore methods
        private ITransactionStore<TApp, TKey> GetTransactionStore()
        {
            var cast = Store as ITransactionStore<TApp, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException("Store Not ITransactionStore");
            }
            return cast;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// 

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        /// <summary>
        ///     When disposing, actually dipose the store
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                Store.Dispose();
                _disposed = true;
            }
        }

        /// <summary>
        ///     Dispose this object
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
