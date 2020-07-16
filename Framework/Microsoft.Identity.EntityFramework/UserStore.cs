using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.Identity.EntityFramework
{
    public class UserStore<TUser, TKey, TRole, TUserLogin, TUserRole, TUserClaim, TPassword> : UserStore<TUser, TKey, TRole, TUserRole, TPassword>
        , IUserSecurityStampStore<TUser, TKey>
        , IUserEmailStore<TUser, TKey>
        , IUserPhoneNumberStore<TUser, TKey>
        , IUserTwoFactorStore<TUser, TKey>
        , IUserLockoutStore<TUser, TKey>
        , IUserLoginStore<TUser, TKey>
        , IUserClaimStore<TUser, TKey>
        , IUserStore<TUser, TKey>
        where TUser : IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>
        where TRole : IdentityRole<TKey>
        where TPassword : IdentityCryptography<TKey>, new()
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
            var query = from u in _UserStore
                        join ul in _LoginStore on u.Id equals ul.UserId
                        where ul.LoginProvider.Equals(provider, StringComparison.Ordinal) && ul.ProviderKey.Equals(key, StringComparison.Ordinal)
                        select u;
            var user = await query.FirstOrDefaultAsync().WithCurrentCulture();
            if (user != null)
            {
                //    var userId = user.Id;
                //    var query = from ul in _LoginStore
                //                where ul.UserId.Equals(userId)
                //                select ul;
                //    await query.LoadAsync().WithCurrentCulture();
                //await Context.Entry(user).Collection(u => u.Logins).LoadAsync().WithCurrentCulture();
            }
            return user;
            //return await GetUserAggregateAsync(u => u.Id.Equals(userId)).WithCurrentCulture();
        }

        public virtual async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var query = from u in _UserStore
                        join ul in _LoginStore on u.Id equals ul.UserId
                        where u.Id.Equals(userId)
                        select ul;
            var logins = await query.ToListAsync().WithCurrentCulture();
            return logins.Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey)).ToList();
        }

        public virtual async Task AddLoginAsync(TUser user, UserLoginInfo login)
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
            var query = from u in _UserStore
                        join ul in _LoginStore on u.Id equals ul.UserId
                        where ul.LoginProvider.Equals(provider, StringComparison.Ordinal) && ul.ProviderKey.Equals(key, StringComparison.Ordinal)// && u.Id.Equals(userId)
                        select ul;
            var uLogin = await query.FirstOrDefaultAsync().WithCurrentCulture();
            if (uLogin != null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserLoginExists")));
            }

            var userLogin = _LoginStore.Create();
            {
                userLogin.UserId = userId;
                userLogin.LoginProvider = provider;
                userLogin.ProviderKey = key;
            }
            _LoginStore.Add(userLogin);
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

            var userId = user.Id;
            var provider = login.LoginProvider;
            var key = login.ProviderKey;
            var query = from ul in _LoginStore
                        where ul.LoginProvider.Equals(provider, StringComparison.Ordinal) && ul.ProviderKey.Equals(key, StringComparison.Ordinal) && ul.UserId.Equals(userId)
                        select ul;
            IEnumerable<TUserLogin> logins = await query.ToListAsync().WithCurrentCulture();
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

            var userId = user.Id;
            var query = from u in _UserStore
                        join uc in _ClaimStore on u.Id equals uc.UserId
                        where u.Id.Equals(userId)
                        select uc;
            var claims = await query.ToListAsync().WithCurrentCulture();
            return claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
        }

        public virtual async Task AddClaimAsync(TUser user, Claim claim)
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
            var query = from u in _UserStore
                        join uc in _ClaimStore on u.Id equals uc.UserId
                        where uc.ClaimType.Equals(claimType, StringComparison.Ordinal) && uc.ClaimValue.Equals(claimValue, StringComparison.Ordinal) && u.Id.Equals(userId)
                        select uc;
            var uClaim = await query.FirstOrDefaultAsync().WithCurrentCulture();
            if (uClaim != null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserClaimExists")));
            }

            var userClaim = _ClaimStore.Create();
            {
                userClaim.UserId = userId;
                userClaim.ClaimType = claimType;
                userClaim.ClaimValue = claimValue;
            }
            _ClaimStore.Add(userClaim);
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

            var userId = user.Id;
            var claimType = claim.Type;
            var claimValue = claim.Value;
            var query = from uc in _ClaimStore
                        where uc.ClaimValue.Equals(claimValue, StringComparison.Ordinal) && uc.ClaimType.Equals(claimType, StringComparison.Ordinal) && uc.UserId.Equals(userId)
                        select uc;
            IEnumerable<TUserClaim> claims = await query.ToListAsync().WithCurrentCulture();
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

    public class UserStore<TUser, TKey, TRole, TUserRole, TPassword> : UserStore<TUser, TKey, TRole, TUserRole>
        , ICryptographyStore<TUser, TKey>
        //, IQueryableUserStore<TUser, TKey>
        , IUserStore<TUser, TKey>
        , IDisposable
        where TUser : IdentityUser<TKey, TUserRole>
        where TRole : IdentityRole<TKey>
        where TUserRole : IdentityUserRole<TKey>, new()
        where TPassword : IdentityCryptography<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        private DbSet<TUser> _UserStore;
        private DbSet<TPassword> _PasswordStore;

        public UserStore(DbContext context)
            : base(context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            _UserStore = Context.Set<TUser>();
            _PasswordStore = Context.Set<TPassword>();
        }

        public override async Task SetPasswordHashAsync(TUser user, string passwordHash, string privateKey)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var query = from u in _UserStore
                        join up in _PasswordStore on u.Id equals up.UserId
                        where up.UserId.Equals(userId)
                        select up;
            var userPwd = await query.FirstOrDefaultAsync().WithCurrentCulture();
            if (userPwd == null)
            {
                userPwd = _PasswordStore.Create();
                {
                    userPwd.UserId = userId;
                    userPwd.PasswordHash = passwordHash;
                    userPwd.PrivateKey = privateKey;
                }
                _PasswordStore.Add(userPwd);
            }
            else
            {
                {
                    userPwd.PasswordHash = passwordHash;
                    userPwd.PrivateKey = privateKey;
                }
                _PasswordStore.Update(userPwd);
            }
        }

        public override async Task<bool> VerifyPasswordAsync(TUser user, string passwordHash)
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

            var userId = user.Id;
            var query = from u in _UserStore
                        join up in _PasswordStore on u.Id equals up.UserId
                        where up.UserId.Equals(userId)
                        select up;
            var userPwd = await query.SingleOrDefaultAsync().WithCurrentCulture();

            return userPwd != null ? userPwd.PasswordHash.Equals(passwordHash, StringComparison.Ordinal) : false;
        }

        public override async Task<bool> HasPasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var query = from u in _UserStore
                        join up in _PasswordStore on u.Id equals up.UserId
                        where up.UserId.Equals(userId)
                        select up;
            var userPwd = await query.FirstOrDefaultAsync().WithCurrentCulture();

            return userPwd != null && userPwd.PasswordHash != null;
        }

        public override async Task<string> GetPrivateKeyAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var query = from u in _UserStore
                        join up in _PasswordStore on u.Id equals up.UserId
                        where up.UserId.Equals(userId)
                        select up;
            var userPwd = await query.FirstOrDefaultAsync().WithCurrentCulture();

            return userPwd != null ? userPwd.PrivateKey : null;
        }
    }

    public class UserStore<TUser, TKey, TRole, TUserRole>
        : IUserRoleStore<TUser, TKey>
        , IUserPasswordStore<TUser, TKey>
        //, IQueryableUserStore<TUser, TKey>
        , ITransactionStore<TUser, TKey>
        , IUserStore<TUser, TKey>
        , IDisposable
        where TUser : IdentityUser<TKey, TUserRole>
        where TRole : IdentityRole<TKey>
        where TUserRole : IdentityUserRole<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        private DbSet<TUser> _UserStore;
        private DbSet<TUserRole> _UserRoleStore;
        private DbSet<TRole> _RoleStore;

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

            _UserStore = Context.Set<TUser>();
            _UserRoleStore = Context.Set<TUserRole>();
            _RoleStore = Context.Set<TRole>();

            //Context.Database.Log = (sql) =>
            //{
            //    if (string.IsNullOrEmpty(sql) == false)
            //    {
            //        System.Diagnostics.Debug.WriteLine("************sql执行*************");
            //        System.Diagnostics.Debug.WriteLine(sql);
            //        System.Diagnostics.Debug.WriteLine("************sql结束************");
            //    }
            //};

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

        public virtual async Task<TUser> FindByIdAsync(TKey userId)
        {
            ThrowIfDisposed();
            var query = from u in _UserStore
                        where u.Id.Equals(userId)
                        select u;
            var user = await query.FirstOrDefaultAsync().WithCurrentCulture();
            if (user != null)
            {
                //    var userId = user.Id;
                //    var query = from ul in _LoginStore
                //                where ul.UserId.Equals(userId)
                //                select ul;
                //    await query.LoadAsync().WithCurrentCulture();
                //await Context.Entry(user).Collection(u => u.Roles).LoadAsync().WithCurrentCulture();
            }
            return user;
            //return GetUserAggregateAsync(u => u.Id.Equals(userId));
        }

        public virtual async Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();
            var query = from u in _UserStore
                        where u.UserName.ToUpper() == userName.ToUpper()
                        select u;
            var user = await query.FirstOrDefaultAsync().WithCurrentCulture();
            if (user != null)
            {
                //    var userId = user.Id;
                //    var query = from ul in _LoginStore
                //                where ul.UserId.Equals(userId)
                //                select ul;
                //    await query.LoadAsync().WithCurrentCulture();
                //await Context.Entry(user).Collection(u => u.Roles).LoadAsync().WithCurrentCulture();
            }
            return user;
            //return GetUserAggregateAsync(u => u.UserName.ToUpper() == userName.ToUpper());
        }

        public virtual Task SetPasswordHashAsync(TUser user, string passwordHash, string privateKey)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
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
            if (passwordHash == null)
            {
                throw new ArgumentNullException("passwordHash");
            }

            return  Task.FromResult(user.PasswordHash.Equals(passwordHash, StringComparison.Ordinal));
        }

        public virtual Task<bool> HasPasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return  Task.FromResult(user.PasswordHash != null);
        }

        public virtual Task<string> GetPrivateKeyAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return null;
        }

        public virtual async Task<IEnumerable<KeyValuePair<TKey, string>>> GetRolesAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var query = from r in _RoleStore
                        join ur in _UserRoleStore on r.Id equals ur.RoleId
                        where ur.UserId.Equals(userId)
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
            if (roleId == null)
            {
                throw new ArgumentNullException("roleId");
            }

            var userId = user.Id;
            var queryRole = from r in _RoleStore
                            where r.Id.Equals(roleId)
                            select r;
            var role = await queryRole.SingleOrDefaultAsync().WithCurrentCulture();
            if (role == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("RoleNotFound"), role.Name));
            }

            var queryUserRole = from ur in _UserRoleStore
                                where ur.UserId.Equals(userId) && ur.RoleId.Equals(roleId)
                                select ur;
            TUserRole uRole = await queryUserRole.FirstOrDefaultAsync().WithCurrentCulture();
            if (uRole != null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserInRole"), role.Name));
            }

            var userRole = _UserRoleStore.Create();
            {
                userRole.UserId = userId;
                userRole.RoleId = role.Id;
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
            if (roleId == null)
            {
                throw new ArgumentNullException("roleId");
            }

            var userId = user.Id;
            var query = from ur in _UserRoleStore
                        where ur.UserId.Equals(userId) && ur.RoleId.Equals(roleId)
                        select ur;
            IEnumerable<TUserRole> roles = await query.ToListAsync().WithCurrentCulture();
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
            var query = from r in _RoleStore
                        join ur in _UserRoleStore on r.Id equals ur.RoleId
                        where ur.UserId.Equals(userId) && ur.RoleId.Equals(roleId)
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

        //private async Task<TUser> GetUserAggregateAsync(Expression<Func<TUser, bool>> filter)
        //private async Task<TUser> GetUserAggregateAsync(IQueryable<TUser> query)
        //{
        //    //TUser user = await _UserStore.FirstAsync(filter);
        //    var user = await query.FirstOrDefaultAsync().WithCurrentCulture();
        //    if (user != null)
        //    {
        //        //await EnsureClaimsLoaded(user).WithCurrentCulture();
        //        //await EnsureLoginsLoaded(user).WithCurrentCulture();
        //        //await EnsureRolesLoaded(user).WithCurrentCulture();
        //    }
        //    return user;
        //}

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
