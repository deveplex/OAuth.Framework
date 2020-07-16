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
    /*
    public class UserStore<TUser> : UserStore<TUser, string>
        //, Framework.IUserCryptographySecurityStore<TUser, TKey>
        , IUserStore<TUser>
        //, IQueryableUserStore<TUser>
        where TUser : IdentityUser, new()
    {
        private DbSet<User> _UserStore { get { return Context.Set<User>(); } }
        private DbSet<Cryptography> _PasswordStore { get { return Context.Set<Cryptography>(); } }
        private DbSet<UserLogin> _LoginStore { get { return Context.Set<UserLogin>(); } }
        private DbSet<UserClaim> _ClaimStore { get { return Context.Set<UserClaim>(); } }
        private DbSet<UserRole> _UserRoleStore { get { return Context.Set<UserRole>(); } }
        private DbSet<Role> _RoleStore { get { return Context.Set<Role>(); } }

        public UserStore()
            : this(new DbContext("DefaultConnection"))
        {
            DisposeContext = true;
        }

        public UserStore(DbContext context)
            : base(context)
        {
        }

        #region 重写
        public override async Task CreateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var account = new User
            {
                UserId = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                SecurityStamp = user.SecurityStamp,
                LockoutEnabled = user.LockoutEnabled,
                LockoutEndDateUtc = user.LockoutEndDateUtc,
                TwoFactorEnabled = user.TwoFactorEnabled,
                AccessFailedCount = user.AccessFailedCount,
                Status = AccountStatus.Enabled,
            };
            account.CheckCode = account.Signature();

            _UserStore.Add(account);
            //await CommitChangesAsync().WithCurrentCulture();

            user.Id = account.UserId;
            await Task.FromResult(0);
        }

        public override async Task UpdateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var account = await _UserStore.SingleOrDefaultAsync(u => u.UserId.Equals(user.Id)).WithCurrentCulture();
            account.UserName = user.UserName;
            account.Email = user.Email;
            account.EmailConfirmed = user.EmailConfirmed;
            account.PhoneNumber = user.PhoneNumber;
            account.PhoneNumberConfirmed = user.PhoneNumberConfirmed;
            account.SecurityStamp = user.SecurityStamp;
            account.LockoutEnabled = user.LockoutEnabled;
            account.LockoutEndDateUtc = user.LockoutEndDateUtc;
            account.TwoFactorEnabled = user.TwoFactorEnabled;
            account.AccessFailedCount = user.AccessFailedCount;
            account.CheckCode = account.Signature();

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

            var account = await _UserStore.SingleOrDefaultAsync(u => u.UserId.Equals(user.Id)).WithCurrentCulture();
            _UserStore.Remove(account);
            //await CommitChangesAsync().WithCurrentCulture();
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

        //public override Task<TUser> FindByEmailAsync(string email)
        //{
        //    ThrowIfDisposed();
        //    return GetUserAggregateAsync(u => u.Email.ToUpper() == email.ToUpper());
        //}

        public override async Task<TUser> FindAsync(UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            var provider = login.LoginProvider;
            var key = login.ProviderKey;
            var query = from ul in _LoginStore
                        where ul.AuthenticationProvider.Equals(provider) && ul.AuthenticationKey.Equals(key)
                        select ul;
            var entry = await query.SingleOrDefaultAsync().WithCurrentCulture();
            if (entry != null)
            {
                var userId = entry.UserId;
                return await GetUserAggregateAsync(u => u.UserId.Equals(userId)).WithCurrentCulture();
            }
            return null;
        }

        public override async Task AddPasswordHashAsync(TUser user, string passwordHash, string privateHash)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            var account = await _UserStore.SingleOrDefaultAsync(u => u.UserId.Equals(user.Id)).WithCurrentCulture();
            account.PasswordHash = passwordHash;
            _UserStore.Update(account);
        }

        public override async Task SetPasswordHashAsync(TUser user, string passwordHash, string privateHash)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var account = await _UserStore.SingleOrDefaultAsync(u => u.UserId.Equals(user.Id)).WithCurrentCulture();
            account.PasswordHash = passwordHash;
            _UserStore.Update(account);
        }

        public override async Task<bool> VerifyPasswordAsync(TUser user, string passwordHash)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var account = await _UserStore.SingleOrDefaultAsync(u => u.UserId.Equals(user.Id, StringComparison.Ordinal)).WithCurrentCulture();
            return await Task.FromResult(account.PasswordHash == passwordHash);
        }

        public override async Task<bool> HasPasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var account = await _UserStore.SingleOrDefaultAsync(u => u.UserId.Equals(user.Id)).WithCurrentCulture();
            return await Task.FromResult(account.PasswordHash != null);
        }

        public override Task<string> GetHashKeyAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public override async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var query = from ul in _LoginStore
                        where ul.UserId.Equals(userId)
                        select ul;
            var logins = await query.ToListAsync().WithCurrentCulture();
            return logins.Select(l => new UserLoginInfo(l.AuthenticationProvider, l.AuthenticationKey)).ToList();
        }

        public override Task AddLoginAsync(TUser user, UserLoginInfo login)
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
            _LoginStore.Add(new UserLogin
            {
                UserId = userId,
                AuthenticationProvider = provider,
                AuthenticationKey = key
            });

            return Task.FromResult(0);
        }

        public override async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
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
                        where ul.AuthenticationProvider.Equals(provider) && ul.AuthenticationKey.Equals(key) && ul.UserId.Equals(userId)
                        select ul;
            var logins = await query.ToListAsync().WithCurrentCulture();
            foreach (var l in logins)
            {
                _LoginStore.Remove(l);
            }
        }

        public override async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var query = from uc in _ClaimStore
                        where uc.UserId.Equals(userId)
                        select uc;
            var claims = await query.ToListAsync().WithCurrentCulture();
            return claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
        }

        public override async Task AddClaimAsync(TUser user, Claim claim)
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
            _ClaimStore.Add(new UserClaim
            {
                UserId = userId,
                ClaimType = claimType,
                ClaimValue = claimValue
            });

            await Task.FromResult(0);
        }

        public override async Task RemoveClaimAsync(TUser user, Claim claim)
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
                        where uc.ClaimValue == claimValue && uc.ClaimType == claimType && uc.UserId.Equals(userId)
                        select uc;
            var claims = await query.ToListAsync().WithCurrentCulture();
            foreach (var c in claims)
            {
                _ClaimStore.Remove(c);
            }
        }

        public override async Task<IEnumerable<KeyValuePair<string, string>>> GetRolesAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var query = from r in _RoleStore
                        join ur in _UserRoleStore on r.RoleId equals ur.RoleId
                        where ur.UserId.Equals(userId)
                        select r;
            var roles = await query.ToListAsync().WithCurrentCulture();
            return roles.Select(r => new KeyValuePair<string, string>(r.RoleId, r.Name)).ToList();
        }

        public override async Task AddToRoleAsync(TUser user, string roleId)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var query = from r in _RoleStore
                        where r.RoleId.Equals(roleId)
                        select r;
            var entity = await query.FirstOrDefaultAsync().WithCurrentCulture();
            if (entity == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("RoleNotFound"), roleId));
            }

            _UserRoleStore.Add(new UserRole
            {
                UserId = userId,
                RoleId = entity.RoleId
            });
        }

        public override async Task RemoveFromRoleAsync(TUser user, string roleId)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var query = from ur in _UserRoleStore
                        where ur.UserId.Equals(userId) && ur.RoleId.Equals(roleId)
                        select ur;
            var roles = await query.ToListAsync().WithCurrentCulture();
            foreach (var r in roles)
            {
                _UserRoleStore.Remove(r);
            }
        }

        public override async Task<bool> IsInRoleAsync(TUser user, string roleId)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userId = user.Id;
            var query = from ur in _UserRoleStore
                        where ur.UserId.Equals(userId) && ur.RoleId.Equals(roleId)
                        join r in _RoleStore on ur.RoleId equals r.RoleId
                        select r;
            return await query.AnyAsync().WithCurrentCulture();
        }

        //public virtual Task SetCryptographySecurityAsync(TUser user, SecurityInfo info)
        //{
        //    throw new NotImplementedException();
        //}

        //public virtual Task<SecurityInfo> GetCryptographySecurityAsync(TUser user)
        //{
        //    throw new NotImplementedException();
        //}

        public override Task<string> GetSecurityStampAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.SecurityStamp = user.SecurityStamp ?? Guid.NewGuid().ToString();
            return Task.FromResult(user.SecurityStamp);
        }

        public override Task SetSecurityStampAsync(TUser user, string stamp)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        }

        public override Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.TwoFactorEnabled);
        }

        public override Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.TwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        public override Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.LockoutEndDateUtc.HasValue
                    ? new DateTimeOffset(DateTime.SpecifyKind(user.LockoutEndDateUtc.Value, DateTimeKind.Utc))
                    : new DateTimeOffset());
        }

        public override Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.LockoutEndDateUtc = lockoutEnd == DateTimeOffset.MinValue ? (DateTime?)null : lockoutEnd.UtcDateTime;
            return Task.FromResult(0);
        }

        public override Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }

        public override Task ResetAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }

        public override Task<int> GetAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.AccessFailedCount);
        }

        public override Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.LockoutEnabled);
        }

        public override Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.LockoutEnabled = enabled;
            return Task.FromResult(0);
        }

        public override Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        public override Task<string> GetPhoneNumberAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.PhoneNumber);
        }

        public override Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public override Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.PhoneNumberConfirmed = confirmed;
            return Task.FromResult(0);
        }

        public override Task SetEmailAsync(TUser user, string email)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.Email = email;
            return Task.FromResult(0);
        }

        public override Task<string> GetEmailAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.Email);
        }

        public override Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult(user.EmailConfirmed);
        }

        public override Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.EmailConfirmed = confirmed;
            return Task.FromResult(0);
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////

        private async Task EnsureLoginsLoaded(TUser user)
        {
                var userId = user.Id;
                var query = from ul in _LoginStore
                            where ul.UserId.Equals(userId)
                            select ul;
                await query.LoadAsync().WithCurrentCulture();
        }

        private async Task EnsureClaimsLoaded(TUser user)
        {
                var userId = user.Id;
                var query = from uc in _ClaimStore
                            where uc.UserId.Equals(userId)
                            select uc;
                await query.LoadAsync().WithCurrentCulture();
        }

        private async Task EnsureRolesLoaded(TUser user)
        {
                var userId = user.Id;
                var query = from ur in _UserRoleStore
                            where ur.UserId.Equals(userId)
                            join r in _RoleStore on ur.RoleId equals r.RoleId
                            select ur;
                await query.LoadAsync().WithCurrentCulture();
        }

        private async Task<TUser> GetUserAggregateAsync(Expression<Func<User, bool>> filter)
        {
            //TKey id;
            TUser user = null;
            var account = await _UserStore.FindAsync(filter).WithCurrentCulture();
            if (account != null)
            {
                user = new TUser
                {
                    Id = account.UserId,
                    UserName = account.UserName,
                    Email = account.Email,
                    EmailConfirmed = account.EmailConfirmed,
                    PhoneNumber = account.PhoneNumber,
                    PhoneNumberConfirmed = account.PhoneNumberConfirmed,
                    SecurityStamp = account.SecurityStamp,
                    LockoutEnabled = account.LockoutEnabled,
                    LockoutEndDateUtc = account.LockoutEndDateUtc,
                    TwoFactorEnabled = account.TwoFactorEnabled,
                    AccessFailedCount = account.AccessFailedCount,
                };
            }
            if (user != null)
            {
                await EnsureClaimsLoaded(user).WithCurrentCulture();
                await EnsureLoginsLoaded(user).WithCurrentCulture();
                await EnsureRolesLoaded(user).WithCurrentCulture();
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
            if (DisposeContext && disposing && Context != null)
            {
                base.Dispose();
            }
            //_userStore = null;
            //_loginStore = null;
            //_claimStore = null;
            //_userroleStore = null;
            //_roleStore = null;
        }
    }
*/

    public class UserStore<TUser> : UserStore<TUser, string, IdentityRole, IdentityUserLogin, IdentityUserRole, IdentityUserClaim, IdentityCryptography>
        //, Framework.IUserCryptographySecurityStore<TUser, TKey>
        , IUserStore<TUser>
        //, IQueryableUserStore<TUser>
        where TUser : IdentityUser, new()
    {
        public UserStore(DbContext context)
            : base(context)
        {
        }
    }
}
