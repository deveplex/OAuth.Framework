using Microsoft.AspNet.Identity.Framework;
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
    public class UserStore<TUser, TKey, TRole, TUserLogin, TUserRole, TUserClaim> : UserStore<TUser, TKey, TRole, TUserRole>
        , IUserSecurityStampStore<TUser, TKey>
        , Framework.IUserEmailStore<TUser, TKey>
        , IUserPhoneNumberStore<TUser, TKey>
        , IUserTwoFactorStore<TUser, TKey>
        , IUserLockoutStore<TUser, TKey>
        , IUserLoginStore<TUser, TKey>
        , IUserClaimStore<TUser, TKey>
        , IUserStore<TUser, TKey>
        where TUser : IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>
        where TRole : IdentityRole<TKey>
        where TUserLogin : IdentityUserLogin<TKey>, new()
        where TUserRole : IdentityUserRole<TKey>, new()
        where TUserClaim : IdentityUserClaim<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        private readonly DbSet<TUser> _UserStore;
        private readonly DbSet<TUserLogin> _LoginStore;
        private readonly DbSet<TUserClaim> _ClaimStore;

        public UserStore(DbContext context)
            : base(context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            _UserStore = Context.Set<TUser>();
            _LoginStore = Context.Set<TUserLogin>();
            _ClaimStore = Context.Set<TUserClaim>();
        }

        public virtual async Task<TUser> FindAsync(UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            var provider = login.LoginProvider;
            var key = login.ProviderKey;
            var query = from ul in _LoginStore
                        where ul.LoginProvider.Equals(provider, StringComparison.Ordinal) && ul.ProviderKey.Equals(key, StringComparison.Ordinal)
                        select ul;
            var entry = await query.FirstOrDefaultAsync().WithCurrentCulture();
            if (entry != null)
            {
                var userId = entry.UserId;
                //return await GetUserAggregateAsync(u => u.Id.Equals(userId)).WithCurrentCulture();
            }
            return null;
        }

        public virtual async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            //await EnsureLoginsLoaded(user).WithCurrentCulture();
            //return user.Logins.Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey)).ToList();

            var query = from u in _UserStore
                        join ul in _LoginStore on u.Id equals ul.UserId
                        select ul;
            var logins = await query.ToListAsync().WithCurrentCulture();
            return logins.Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey)).ToList();
        }

        public virtual Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            var userId = user.Id;
            var provider = login.LoginProvider;
            var key = login.ProviderKey;
            var userLogin = _LoginStore.Create();
            {
                userLogin.UserId = userId;
                userLogin.LoginProvider = provider;
                userLogin.ProviderKey = key;
            }
            _LoginStore.Add(userLogin);
            return Task.FromResult(0);
        }

        public virtual async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            IEnumerable<TUserLogin> logins;
            var userId = user.Id;
            var provider = login.LoginProvider;
            var key = login.ProviderKey;
            var query = from ul in _LoginStore
                        where ul.LoginProvider.Equals(provider, StringComparison.Ordinal) && ul.ProviderKey.Equals(key, StringComparison.Ordinal) && ul.UserId.Equals(userId)
                        select ul;
            logins = await query.ToListAsync().WithCurrentCulture();
            foreach (var l in logins)
            {
                _LoginStore.Remove(l);
            }
        }

        public virtual async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            //await EnsureClaimsLoaded(user).WithCurrentCulture();
            //return user.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();

            var query = from u in _UserStore
                        join uc in _ClaimStore on u.Id equals uc.UserId
                        select uc;
            var claims = await query.ToListAsync().WithCurrentCulture();
            return claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
        }

        public virtual Task AddClaimAsync(TUser user, Claim claim)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }

            var userId = user.Id;
            var claimType = claim.Type;
            var claimValue = claim.Value;
            var userClaim = _ClaimStore.Create();
            {
                userClaim.UserId = userId;
                userClaim.ClaimType = claimType;
                userClaim.ClaimValue = claimValue;
            }
            _ClaimStore.Create();
            _ClaimStore.Add(userClaim);
            return Task.FromResult(0);
        }

        public virtual async Task RemoveClaimAsync(TUser user, Claim claim)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }

            IEnumerable<TUserClaim> claims;
            var userId = user.Id;
            var claimType = claim.Type;
            var claimValue = claim.Value;
            var query = from uc in _ClaimStore
                        where uc.ClaimValue.Equals(claimValue, StringComparison.Ordinal) && uc.ClaimType.Equals(claimType, StringComparison.Ordinal) && uc.UserId.Equals(userId)
                        select uc;
            claims = await query.ToListAsync().WithCurrentCulture();
            foreach (var c in claims)
            {
                _ClaimStore.Remove(c);
            }
        }

        public virtual Task<string> GetSecurityStampAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.SecurityStamp);
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

        public virtual Task<string> GetPhoneNumberAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.PhoneNumber);
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

        public virtual Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
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

        public virtual Task<string> GetEmailAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.Email);
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

        public virtual Task SetEmailAsync(TUser user, string email)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.Email = email;
            return Task.FromResult(0);
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

        public virtual Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.LockoutEndDate.HasValue
                    ? new DateTimeOffset(DateTime.SpecifyKind(user.LockoutEndDate.Value, DateTimeKind.Utc))
                    : new DateTimeOffset());
        }

        public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.LockoutEndDate = lockoutEnd == DateTimeOffset.MinValue ? (DateTime?)null : lockoutEnd.UtcDateTime;
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

        public virtual Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.TwoFactorEnabled);
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
    }

    public class UserStore<TUser, TKey, TRole, TUserRole>
        : Framework.IUserRoleStore<TUser, TKey>
        , Framework.IUserPasswordStore<TUser, TKey>
        //, IQueryableUserStore<TUser, TKey>
        , Framework.ITransactionStore<TUser, TKey>
        , IUserStore<TUser, TKey>
        , IDisposable
        where TUser : IdentityUser<TKey, TUserRole>
        where TRole : IdentityRole<TKey>
        where TUserRole : IdentityUserRole<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        private DbSet<TUser> _UserStore { get { return Context.Set<TUser>(); } }
        private DbSet<TUserRole> _UserRoleStore { get { return Context.Set<TUserRole>(); } }
        private DbSet<TRole> _RoleStore { get { return Context.Set<TRole>(); } }

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

            //_UserStore = Context.Set<TUser>();
            //_UserRoleStore = Context.Set<TUserRole>();
            //_RoleStore = Context.Set<TRole>();

            Context.Database.Log = (sql) =>
            {
                if (string.IsNullOrEmpty(sql) == false)
                {
                    System.Diagnostics.Debug.WriteLine("************sql执行*************");
                    System.Diagnostics.Debug.WriteLine(sql);
                    System.Diagnostics.Debug.WriteLine("************sql结束************");
                }
            };

        }

        protected DbContext Context { get; private set; }

        public virtual Task CreateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            _UserStore.Add(user);
            return Task.FromResult(0);
        }

        public virtual Task UpdateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            _UserStore.Update(user);
            return Task.FromResult(0);
        }

        public virtual Task DeleteAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            _UserStore.Remove(user);
            return Task.FromResult(0);
        }

        public virtual Task<TUser> FindByIdAsync(TKey userId)
        {
            ThrowIfDisposed();
            return GetUserAggregateAsync(u => u.Id.Equals(userId));
        }

        public virtual async Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();
            //System.Collections.Generic.List<TRole> users = Context.Database.SqlQuery<TRole>("SELECT * FROM [Roles]", new object[] { }).ToListAsync().Result;

            //Task<TUser> user = _UserStore.Where(u=>u.UserName==userName).FirstOrDefaultAsync();
            var query = from u in _UserStore.AsNoTracking()
                        where u.UserName.ToUpper() == userName.ToUpper()
                        select u;
            var user = await query.FirstOrDefaultAsync().WithCurrentCulture();

            return user;
            //return GetUserAggregateAsync(u => u.UserName.ToUpper() == userName.ToUpper());
        }

        #region Obsolete Password
        [Obsolete("", false)]
        public Task<string> GetPasswordHashAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        [Obsolete("", false)]
        public Task SetPasswordHashAsync(TUser user, string password)
        {
            throw new NotImplementedException();
        }
        #endregion

        public virtual Task AddPasswordHashAsync(TUser user, string passwordHash, string privateHash)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (passwordHash == null)
            {
                throw new ArgumentNullException("passwordHash");
            }
            if (privateHash == null)
            {
                throw new ArgumentNullException("privateHash");
            }

            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        public virtual Task SetPasswordHashAsync(TUser user, string passwordHash, string privateHash)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (passwordHash == null)
            {
                throw new ArgumentNullException("passwordHash");
            }
            if (privateHash == null)
            {
                throw new ArgumentNullException("privateHash");
            }

            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        public virtual Task<bool> VerifyPasswordAsync(TUser user, string passwordHash)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.PasswordHash.Equals(passwordHash, StringComparison.Ordinal));
        }

        public virtual Task<bool> HasPasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.PasswordHash != null);
        }

        public virtual Task<string> GetHashKeyAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public virtual async Task<IEnumerable<KeyValuePair<TKey, string>>> GetRolesAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var query = from u in _UserStore
                        join ur in _UserRoleStore on u.Id equals ur.UserId
                        join r in _RoleStore on ur.RoleId equals r.Id
                        select r;
            var roles = await query.ToListAsync().WithCurrentCulture();
            return roles.Select(r => new KeyValuePair<TKey, string>(r.Id, r.Name)).ToList();
        }

        public virtual async Task AddToRoleAsync(TUser user, TKey roleId)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var query = from r in _RoleStore
                        where r.Id.Equals(roleId)
                        select r;
            var entity = await query.SingleOrDefaultAsync().WithCurrentCulture();
            if (entity == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("RoleNotFound"), roleId));
            }

            var userRole = _UserRoleStore.Create();
            {
                userRole.UserId = userId;
                userRole.RoleId = entity.Id;
            }
            _UserRoleStore.Add(userRole);
        }

        public virtual async Task RemoveFromRoleAsync(TUser user, TKey roleId)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            IEnumerable<TUserRole> roles;
            var userId = user.Id;
            var query = from ur in _UserRoleStore
                        where ur.UserId.Equals(userId) && ur.RoleId.Equals(roleId)
                        select ur;
            roles = await query.ToListAsync().WithCurrentCulture();
            foreach (var r in roles)
            {
                _UserRoleStore.Remove(r);
            }
        }

        public virtual async Task<bool> IsInRoleAsync(TUser user, TKey roleId)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var query = from ur in _UserRoleStore
                        where ur.UserId.Equals(userId) && ur.RoleId.Equals(roleId)
                        join r in _RoleStore on ur.RoleId equals r.Id
                        select r;
            return await query.AnyAsync().WithCurrentCulture();
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////

        //private async Task EnsureLoginsLoaded(TUser user)
        //{
        //    var userId = user.Id;
        //    var query = from ul in _LoginStore
        //                where ul.UserId.Equals(userId)
        //                select ul;
        //    await query.LoadAsync().WithCurrentCulture();
        //}

        //private async Task EnsureClaimsLoaded(TUser user)
        //{
        //    var userId = user.Id;
        //    var query = from uc in _ClaimStore
        //                where uc.UserId.Equals(userId)
        //                select uc;
        //    await query.LoadAsync().WithCurrentCulture();
        //}

        //private async Task EnsureRolesLoaded(TUser user)
        //{
        //    var userId = user.Id;
        //    var query = from ur in _UserRoleStore
        //                where ur.UserId.Equals(userId)
        //                join r in _RoleStore on ur.RoleId equals r.Id
        //                select ur;
        //    await query.LoadAsync().WithCurrentCulture();
        //}

        private async Task<TUser> GetUserAggregateAsync(Expression<Func<TUser, bool>> filter)
        {
            TUser user = await _UserStore.FirstAsync(filter);
            if (user != null)
            {
                //await EnsureClaimsLoaded(user).WithCurrentCulture();
                //await EnsureLoginsLoaded(user).WithCurrentCulture();
                //await EnsureRolesLoaded(user).WithCurrentCulture();
            }
            return user;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////

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
            //_UserStore = null;
            //_LoginStore = null;
            //_ClaimStore = null;
            //_UserRoleStore = null;
            //_RoleStore = null;
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
