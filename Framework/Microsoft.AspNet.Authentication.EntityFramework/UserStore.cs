using Deveplex.Authentication.Entity;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity.EntityFramework
{
    public class UserStore<TUser> : UserStore<TUser, string>
        , IUserStore<TUser>
        //, IQueryableUserStore<TUser>
        where TUser : IdentityUser, new()
    {
        private EntityStore<Account> _UserStore;
        private EntityStore<ExternalAccount> _ExternalStore;
        private EntityStore<CryptographySecurity> _CryptoStore;
        private EntityStore<AccountAttribute> _AttributeStore;
        //private readonly EntityStore<Role> _roleStore;

        public UserStore()
            : this(new DbContext("DefaultConnection"))
        {
            DisposeContext = true;
        }

        public UserStore(DbContext context)
            : base(context)
        {
            _UserStore = new EntityStore<Account>(context);
            _ExternalStore = new EntityStore<ExternalAccount>(context);
            _CryptoStore = new EntityStore<CryptographySecurity>(context);
            _AttributeStore = new EntityStore<AccountAttribute>(context);
            //_roleStore = new EntityStore<Role>(context);
        }

        #region 重写
        public override async Task CreateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var account = _UserStore.Add(new Account
            {
                UserId = user.Id,
                UserName = user.UserName,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                SecurityStamp = user.SecurityStamp,
                LockoutEnabled = user.LockoutEnabled,
                LockoutEndDateUtc = user.LockoutEndDateUtc,
                TwoFactorEnabled = user.TwoFactorEnabled,
                AccessFailedCount = user.AccessFailedCount,
                Status = AccountStatus.Enabled
            });
            //await CommitChangesAsync().WithCurrentCulture();
            await Task.FromResult(0);
        }

        public override async Task UpdateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId)).WithCurrentCulture();
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                   "User {0} not found", userId));
            }
            account.UserName = user.UserName;
            account.EmailConfirmed = user.EmailConfirmed;
            account.PhoneNumberConfirmed = user.PhoneNumberConfirmed;
            account.SecurityStamp = user.SecurityStamp;
            account.LockoutEnabled = user.LockoutEnabled;
            account.LockoutEndDateUtc = user.LockoutEndDateUtc;
            account.TwoFactorEnabled = user.TwoFactorEnabled;
            account.AccessFailedCount = user.AccessFailedCount;
            _UserStore.Update(account);
            //await CommitChangesAsync().WithCurrentCulture();
        }

        public override async Task DeleteAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(user.Id)).WithCurrentCulture();
            if (account == null)
            {
                return;
            }
            _UserStore.Remove(account);
            //await SaveChangesAsync().WithCurrentCulture();
        }

        public override Task<TUser> FindByIdAsync(string userId)
        {
            ThrowIfDisposed();
            return GetUserAggregateAsync(u => u.UserId.Equals(userId));
        }

        public override Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();
            return GetUserAggregateAsync(u => u.UserName.ToUpper() == userName.ToUpper());
        }

        public override async Task<TUser> FindAsync(Framework.ExternalAccountInfo info)
        {
            ThrowIfDisposed();
            if (info == null)
            {
                throw new ArgumentNullException("info");
            }

            var provider = info.ExternalProvider;
            var key = info.ProviderKey;
            var query = from ea in _ExternalStore.Entities
                        where ea.ExternalProvider.Equals(provider) && ea.ProviderKey.Equals(key)
                        select ea;
            var entry = await query.SingleOrDefaultAsync().WithCurrentCulture();
            if (entry != null)
            {
                var accountId = entry.AccountId;
                return await GetUserAggregateAsync(u => u.AccountId.Equals(accountId)).WithCurrentCulture();
            }
            return null;
        }

        public override async Task<IList<Framework.ExternalAccountInfo>> GetExternalAccountAsync(TUser user)
        {
            var query = from a in _UserStore.Entities
                        where a.UserId.Equals(user.Id)
                        join ea in _ExternalStore.Entities on a.AccountId equals ea.AccountId
                        select ea;
            var externals = await query.ToListAsync().WithCurrentCulture();
            return externals.Select(e => new Framework.ExternalAccountInfo(e.ExternalProvider, e.ProviderKey)).ToList();
        }

        public override async Task AddExternalAccountAsync(TUser user, Framework.ExternalAccountInfo info)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (info == null)
            {
                throw new ArgumentNullException("info");
            }

            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                   "User {0} not found", userId));
            }
            var accountId = account.AccountId;
            var provider = info.ExternalProvider;
            var key = info.ProviderKey;
            _ExternalStore.Add(new ExternalAccount
            {
                AccountId = accountId,
                ExternalProvider = provider,
                ProviderKey = key
            });
        }

        public override async Task RemoveExternalAccountAsync(TUser user, Framework.ExternalAccountInfo info)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (info == null)
            {
                throw new ArgumentNullException("info");
            }

            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                   "User {0} not found", userId));
            }
            var accountId = account.AccountId;
            var provider = info.ExternalProvider;
            var key = info.ProviderKey;
            var query = from ea in _ExternalStore.Entities
                        where ea.ExternalProvider.Equals(provider) && ea.ProviderKey.Equals(key) && ea.AccountId.Equals(accountId)
                        select ea;
            var externals = await query.ToListAsync().WithCurrentCulture();
            foreach (var e in externals)
            {
                _ExternalStore.Remove(e);
            }
        }

        public override async Task<bool> HasExternalAccountProviderAsync(TUser user, Framework.ExternalAccountInfo info)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (info == null)
            {
                throw new ArgumentNullException("info");
            }

            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                   "User {0} not found", userId));
            }
            var accountId = account.AccountId;
            var provider = info.ExternalProvider;
            var key = info.ProviderKey;
            var query = from ea in _ExternalStore.Entities
                        where ea.ExternalProvider.Equals(provider) && ea.AccountId.Equals(accountId)
                        select ea;
            var external = await query.FirstOrDefaultAsync().WithCurrentCulture();
            return external != null;
        }

        public override async Task<Framework.ExternalAttributeInfo> GetAccountAttributeAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                    "User {0} not found", userId));
            }
            var accountId = account.AccountId;
            var query = from aa in _AttributeStore.Entities
                        where aa.AccountId.Equals(accountId)
                        select aa;
            var attributes = await query.ToListAsync().WithCurrentCulture();
            return attributes.Select(x => new Framework.ExternalAttributeInfo
            {
                AccountType = (int)x.AccountType,
                IsResetPassword = x.IsResetPassword,
                IsResetUserName = x.IsResetUserName,
                NameIsValidated = x.NameIsValidated,
                EmailIsValidated = x.EmailIsValidated,
                MobileIsValidated = x.MobileIsValidated,
                ZuluTime = x.ZuluTime
            }).FirstOrDefault();
        }

        public override async Task AddAccountAttributeAsync(TUser user, Framework.ExternalAttributeInfo info)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (!Enum.IsDefined(typeof(AccountTypes), info.AccountType))
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                    "Invalid AccountType", info.AccountType));
            }

            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                    "User {0} not found", userId));
            }
            var accountId = account.AccountId;
            _AttributeStore.Add(new AccountAttribute
            {
                AccountId = accountId,
                AccountType = (AccountTypes)info.AccountType,
                IsResetPassword = info.IsResetPassword,
                IsResetUserName = info.IsResetUserName,
                NameIsValidated = info.NameIsValidated,
                EmailIsValidated = info.EmailIsValidated,
                MobileIsValidated = info.MobileIsValidated,
                ZuluTime = info.ZuluTime
            });
        }

        public override async Task SetAccountAttributeAsync(TUser user, Framework.ExternalAttributeInfo info)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (!Enum.IsDefined(typeof(AccountTypes), info.AccountType))
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                    "Invalid AccountType", info.AccountType));
            }

            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                    "User {0} not found", userId));
            }
            var accountId = account.AccountId;
            var query = from aa in _AttributeStore.Entities
                        where aa.AccountId.Equals(accountId)
                        select aa;
            var attribute = await query.FirstOrDefaultAsync().WithCurrentCulture();
            attribute.AccountType = (AccountTypes)info.AccountType;
            attribute.IsResetPassword = info.IsResetPassword;
            attribute.IsResetUserName = info.IsResetUserName;
            attribute.NameIsValidated = info.NameIsValidated;
            attribute.EmailIsValidated = info.EmailIsValidated;
            attribute.MobileIsValidated = info.MobileIsValidated;
            attribute.ZuluTime = info.ZuluTime;
            _AttributeStore.Update(attribute);
        }

        public override async Task<bool> HasAccountAttributeAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                    "User {0} not found", userId));
            }
            var accountId = account.AccountId;
            var query = from aa in _AttributeStore.Entities
                        where aa.AccountId.Equals(accountId)
                        select aa;
            var attribute = await query.FirstOrDefaultAsync().WithCurrentCulture();
            return attribute != null;
        }

        public override async Task AddPasswordAsync(TUser user, string password)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                   "User {0} not found", userId));
            }
            account.PasswordHash = password;
            _UserStore.Update(account);
        }

        public override async Task SetPasswordAsync(TUser user, string password)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                   "User {0} not found", userId));
            }
            account.PasswordHash = password;
            _UserStore.Update(account);
        }

        public override async Task<bool> VerifyPasswordAsync(TUser user, string password)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                    "User {0} not found", userId));
            }
            return account.PasswordHash.Equals(password, StringComparison.Ordinal);
        }

        public override async Task<bool> HasPasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                    "User {0} not found", userId));
            }
            return account.PasswordHash != null;
        }

        public override async Task AddSecurityPasswordAsync(TUser user, string password, string PrivateKey)
        {
            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                   "User {0} not found", userId));
            }
            var accountId = account.AccountId;
            _CryptoStore.Add(new CryptographySecurity
            {
                AccountId = accountId,
                Password = password,
                PrivateKey = PrivateKey
            });
        }

        public override async Task SetSecurityPasswordAsync(TUser user, string password, string PrivateKey)
        {
            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                   "User {0} not found", userId));
            }
            var accountId = account.AccountId;
            var crypto = await _CryptoStore.Entities.SingleOrDefaultAsync(us => us.AccountId.Equals(accountId)).WithCurrentCulture();
            crypto.Password = password;
            crypto.PrivateKey = PrivateKey;
            _CryptoStore.Update(crypto);
        }

        public override async Task<bool> VerifySecurityPasswordAsync(TUser user, string password)
        {
            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                   "User {0} not found", userId));
            }
            var accountId = account.AccountId;
            var crypto = await _CryptoStore.Entities.SingleOrDefaultAsync(us => us.AccountId.Equals(accountId)).WithCurrentCulture();
            return crypto.Password.Equals(password, StringComparison.Ordinal);
        }

        public override async Task<Framework.SecurityInfo> GetCryptographySecurityAsync(TUser user)
        {
            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                   "User {0} not found", userId));
            }
            var accountId = account.AccountId;
            var crypto = await _CryptoStore.Entities.FirstOrDefaultAsync(us => us.AccountId.Equals(accountId)).WithCurrentCulture();
            if (crypto == null)
            {
                return null;
            }
            return new Framework.SecurityInfo { Version = crypto.Version, Format = (int)crypto.Format };
        }

        public override async Task SetCryptographySecurityAsync(TUser user, Framework.SecurityInfo info)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                   "User {0} not found", userId));
            }
            var accountId = account.AccountId;
            var crypto = await _CryptoStore.Entities.SingleOrDefaultAsync(us => us.AccountId.Equals(accountId)).WithCurrentCulture();
            crypto.Version = info.Version;
            crypto.Format = (CryptoFormats)info.Format;
            _CryptoStore.Update(crypto);
        }

        public override async Task<string> GetPrivateKeyAsync(TUser user)
        {
            var userId = user.Id;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(u => u.UserId.Equals(userId));
            if (account == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                   "User {0} not found", userId));
            }
            var accountId = account.AccountId;
            var crypto = await _CryptoStore.Entities.FirstOrDefaultAsync(us => us.AccountId.Equals(accountId)).WithCurrentCulture();
            if (crypto == null)
            {
                return null;
            }
            return crypto.PrivateKey;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        /// <summary>
        /// 
        /// </summary>
        /// <param name="filter"></param>
        /// <returns></returns>
        private async Task<TUser> GetUserAggregateAsync(Expression<Func<Account, bool>> filter)
        {
            //TKey id;
            TUser user = null;
            var account = await _UserStore.Entities.SingleOrDefaultAsync(filter).WithCurrentCulture();
            if (account != null)
            {
                user = new TUser
                {
                    Id = account.UserId,
                    UserName = account.UserName,
                    EmailConfirmed = account.EmailConfirmed,
                    PhoneNumberConfirmed = account.PhoneNumberConfirmed,
                    SecurityStamp = account.SecurityStamp,
                    LockoutEnabled = account.LockoutEnabled,
                    LockoutEndDateUtc = account.LockoutEndDateUtc,
                    TwoFactorEnabled = account.TwoFactorEnabled,
                    AccessFailedCount = account.AccessFailedCount
                };
            }
            if (user != null)
            {
                //await EnsureClaimsLoaded(user).WithCurrentCulture();
                //await EnsureLoginsLoaded(user).WithCurrentCulture();
                //await EnsureRolesLoaded(user).WithCurrentCulture();
            }
            return user;
        }
        #endregion

        ////////////////////////////////////////////////////////////////////////////////////////////////////////

        /// <summary>
        ///     If disposing, calls dispose on the Context.  Always nulls out the Context
        /// </summary>
        /// <param name="disposing"></param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            _UserStore = null;
            _ExternalStore = null;
            _CryptoStore = null;
            _AttributeStore = null;
        }

    }

    public class UserStore<TUser, TKey> : UserStore<TUser, TKey, IdentityRole<TKey>, IdentityUserLogin<TKey>, IdentityUserRole<TKey>, IdentityUserClaim<TKey>>
        , Framework.IUserAccountAttributeStore<TUser, TKey>
        , Framework.IUserExternalAccountStore<TUser, TKey>
        , IUserSecurityStampStore<TUser, TKey>
        , IUserTwoFactorStore<TUser, TKey>
        , IUserLockoutStore<TUser, TKey>
        //, IQueryableUserStore<TUser, TKey>
        , IUserStore<TUser, TKey>
        where TUser : IdentityUser<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        public UserStore()
            : this(new DbContext("DefaultConnection"))
        {
            DisposeContext = true;
        }

        public UserStore(DbContext context)
            : base(context)
        {
        }

        public virtual Task<TUser> FindAsync(Framework.ExternalAccountInfo info)
        {
            throw new NotImplementedException();
        }

        public virtual Task<IList<Framework.ExternalAccountInfo>> GetExternalAccountAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public virtual Task AddExternalAccountAsync(TUser user, Framework.ExternalAccountInfo info)
        {
            throw new NotImplementedException();
        }

        public virtual Task RemoveExternalAccountAsync(TUser user, Framework.ExternalAccountInfo info)
        {
            throw new NotImplementedException();
        }

        public virtual Task<bool> HasExternalAccountProviderAsync(TUser user, Framework.ExternalAccountInfo info)
        {
            throw new NotImplementedException();
        }

        public virtual Task<Framework.ExternalAttributeInfo> GetAccountAttributeAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public virtual Task AddAccountAttributeAsync(TUser user, Framework.ExternalAttributeInfo attribute)
        {
            throw new NotImplementedException();
        }

        public virtual Task SetAccountAttributeAsync(TUser user, Framework.ExternalAttributeInfo attribute)
        {
            throw new NotImplementedException();
        }

        public virtual Task<bool> HasAccountAttributeAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public virtual Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.EmailConfirmed);
        }

        public virtual Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.EmailConfirmed = confirmed;
            return Task.FromResult(0);
        }

        public virtual Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public virtual Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.PhoneNumberConfirmed = confirmed;
            return Task.FromResult(0);
        }

        public virtual Task SetSecurityStampAsync(TUser user, string stamp)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        }

        public virtual Task<string> GetSecurityStampAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.SecurityStamp = user.SecurityStamp;
            return Task.FromResult(user.SecurityStamp);
        }

        public virtual Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.TwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        public virtual Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.TwoFactorEnabled);
        }

        public virtual Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return
                Task.FromResult(user.LockoutEndDateUtc.HasValue
                    ? new DateTimeOffset(DateTime.SpecifyKind(user.LockoutEndDateUtc.Value, DateTimeKind.Utc))
                    : new DateTimeOffset());
        }

        public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.LockoutEndDateUtc = lockoutEnd == DateTimeOffset.MinValue ? (DateTime?)null : lockoutEnd.UtcDateTime;
            return Task.FromResult(0);
        }

        public virtual Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }

        public virtual Task ResetAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }

        public virtual Task<int> GetAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.AccessFailedCount);
        }

        public virtual Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.LockoutEnabled);
        }

        public virtual Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.LockoutEnabled = enabled;
            return Task.FromResult(0);
        }
    }

    public class UserStore<TUser, TKey, TRole, TUserLogin, TUserRole, TUserClaim>
        : Framework.ITransactionStore<TUser, TKey>
        , Framework.IUserPasswordStore<TUser, TKey>
        , Framework.IUserCryptographySecurityStore<TUser, TKey>
        //, Framework.IUserRoleStore<TUser, TKey>
        //, IQueryableUserStore<TUser, TKey>
        , IUserStore<TUser, TKey>
        , IDisposable
        where TUser : IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>, new()
        where TRole : IdentityRole<TKey>, new()
        where TUserLogin : IdentityUserLogin<TKey>, new()
        where TUserRole : IdentityUserRole<TKey>, new()
        where TUserClaim : IdentityUserClaim<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        //private EntityStore<Account<TKey>> _userStore;
        //private EntityStore<UserLogin<TKey>> _loginStore;
        //private EntityStore<UserClaim<TKey>> _claimStore;
        //private EntityStore<UserRole<TKey>> _userroleStore;
        //private EntityStore<Role<TKey>> _roleStore;

        private bool _disposed;

        protected bool DisposeContext { get; set; }

        protected bool AutoSaveChanges { get; set; }

        public UserStore(DbContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            Context = context;
            AutoSaveChanges = true;

            //_userStore = new EntityStore<Account<TKey>>(context);
            //_loginStore = new EntityStore<UserLogin<TKey>>(context);
            //_claimStore = new EntityStore<UserClaim<TKey>>(context);
            //_userroleStore = new EntityStore<UserRole<TKey>>(context);
            //_roleStore = new EntityStore<Role<TKey>>(context);
        }

        protected DbContext Context { get; private set; }

        #region 未实现

        public virtual Task CreateAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public virtual Task UpdateAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public virtual Task DeleteAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public virtual Task<TUser> FindByIdAsync(TKey userId)
        {
            throw new NotImplementedException();
        }

        public virtual Task<TUser> FindByNameAsync(string userName)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetPasswordAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public virtual Task AddPasswordAsync(TUser user, string password)
        {
            throw new NotImplementedException();
        }

        public virtual Task SetPasswordAsync(TUser user, string password)
        {
            throw new NotImplementedException();
        }

        public virtual Task<bool> VerifyPasswordAsync(TUser user, string password)
        {
            throw new NotImplementedException();
        }

        public virtual Task<bool> HasPasswordAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public virtual Task AddSecurityPasswordAsync(TUser user, string password, string PrivateKey)
        {
            throw new NotImplementedException();
        }

        public virtual Task SetSecurityPasswordAsync(TUser user, string password, string PrivateKey)
        {
            throw new NotImplementedException();
        }

        public virtual Task<bool> VerifySecurityPasswordAsync(TUser user, string password)
        {
            throw new NotImplementedException();
        }

        public virtual Task<Framework.SecurityInfo> GetCryptographySecurityAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public virtual Task SetCryptographySecurityAsync(TUser user, Framework.SecurityInfo info)
        {
            throw new NotImplementedException();
        }

        public virtual Task<string> GetPrivateKeyAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        #endregion

        // Only call save changes if AutoSaveChanges is true
        public async Task CommitChangesAsync()
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
            //_userStore = null;
        }

        /// <summary>
        ///     Dispose the store
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #region nnnnnnnnnnnnn
        /*
                // We want to use FindAsync() when looking for an User.Id instead of LINQ to avoid extra 
                // database roundtrips. This class cracks open the filter expression passed by 
                // UserStore.FindByIdAsync() to obtain the value of the id we are looking for 
                private static class FindByIdFilterParser
                {
                    // expression pattern we need to match
                    private static readonly Expression<Func<TUser, bool>> Predicate = u => u.Id.Equals(default(TKey));
                    // method we need to match: Object.Equals() 
                    private static readonly MethodInfo EqualsMethodInfo = ((MethodCallExpression)Predicate.Body).Method;
                    // property access we need to match: User.Id 
                    private static readonly MemberInfo UserIdMemberInfo = ((MemberExpression)((MethodCallExpression)Predicate.Body).Object).Member;

                    internal static bool TryMatchAndGetId(Expression<Func<TUser, bool>> filter, out TKey id)
                    {
                        // default value in case we can’t obtain it 
                        id = default(TKey);

                        // lambda body should be a call 
                        if (filter.Body.NodeType != ExpressionType.Call)
                        {
                            return false;
                        }

                        // actually a call to object.Equals(object)
                        var callExpression = (MethodCallExpression)filter.Body;
                        if (callExpression.Method != EqualsMethodInfo)
                        {
                            return false;
                        }
                        // left side of Equals() should be an access to User.Id
                        if (callExpression.Object == null
                            || callExpression.Object.NodeType != ExpressionType.MemberAccess
                            || ((MemberExpression)callExpression.Object).Member != UserIdMemberInfo)
                        {
                            return false;
                        }

                        // There should be only one argument for Equals()
                        if (callExpression.Arguments.Count != 1)
                        {
                            return false;
                        }

                        MemberExpression fieldAccess;
                        if (callExpression.Arguments[0].NodeType == ExpressionType.Convert)
                        {
                            // convert node should have an member access access node
                            // This is for cases when primary key is a value type
                            var convert = (UnaryExpression)callExpression.Arguments[0];
                            if (convert.Operand.NodeType != ExpressionType.MemberAccess)
                            {
                                return false;
                            }
                            fieldAccess = (MemberExpression)convert.Operand;
                        }
                        else if (callExpression.Arguments[0].NodeType == ExpressionType.MemberAccess)
                        {
                            // Get field member for when key is reference type
                            fieldAccess = (MemberExpression)callExpression.Arguments[0];
                        }
                        else
                        {
                            return false;
                        }

                        // and member access should be a field access to a variable captured in a closure
                        if (fieldAccess.Member.MemberType != MemberTypes.Field
                            || fieldAccess.Expression.NodeType != ExpressionType.Constant)
                        {
                            return false;
                        }

                        // expression tree matched so we can now just get the value of the id 
                        var fieldInfo = (FieldInfo)fieldAccess.Member;
                        var closure = ((ConstantExpression)fieldAccess.Expression).Value;

                        id = (TKey)fieldInfo.GetValue(closure);
                        return true;
                    }
                }
        */
        #endregion //nnnnnnnnnnnnn
    }
}
