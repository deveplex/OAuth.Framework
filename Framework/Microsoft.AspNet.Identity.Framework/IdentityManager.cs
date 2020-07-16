using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     IdentityManager for users where the primary key for the User is of type string
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public class IdentityManager<TUser> : IdentityManager<TUser, string>
        where TUser : class, IUser<string>
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="store"></param>
        public IdentityManager(IUserStore<TUser> store)
            : base(store)
        {
        }
    }

    /// <summary>
    ///     Exposes user related api which will automatically save changes to the UserStore
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public class IdentityManager<TUser, TKey> : UserManager<TUser, TKey>
        where TUser : class, IUser<TKey>
        where TKey : IEquatable<TKey>
    {
        private bool _disposed;

        public IdentityManager(IUserStore<TUser, TKey> store)
            : base(store)
        {
            if (store == null)
            {
                throw new ArgumentNullException("store");
            }

            UserValidator = new IdentityValidator<TUser, TKey>(this);
            PasswordValidator = new UserPasswordValidator();
            PasswordHasher = new CryptographyHasher();
        }

        /// <summary>
        ///     Returns true if the store is an IUserRoleStore
        /// </summary>
        public override bool SupportsUserRole
        {
            get
            {
                ThrowIfDisposed();
                return Store is Framework.IUserRoleStore<TUser, TKey>;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public virtual bool SupportsTransaction
        {
            get
            {
                ThrowIfDisposed();
                return Store is Framework.ITransactionStore<TUser, TKey>;
            }
        }

        /// <summary>
        ///     Create a user with no password
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> CreateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var result = await UserValidator.ValidateAsync(user).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            if (SupportsUserSecurityStamp)
            {
                var securityStampStore = GetSecurityStampStore();
                await securityStampStore.SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
            }
            if (UserLockoutEnabledByDefault && SupportsUserLockout)
            {
                var lockoutStore = GetUserLockoutStore();
                await lockoutStore.SetLockoutEnabledAsync(user, true).WithCurrentCulture();
            }
            await Store.CreateAsync(user).WithCurrentCulture();
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Update a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> UpdateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var result = await UserValidator.ValidateAsync(user).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            await Store.UpdateAsync(user).WithCurrentCulture();
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Delete a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> DeleteAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            await Store.DeleteAsync(user).WithCurrentCulture();
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Find a user by id
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public override async Task<TUser> FindByIdAsync(TKey userId)
        {
            ThrowIfDisposed();
            return await Store.FindByIdAsync(userId).WithCurrentCulture();
        }

        /// <summary>
        ///     Find a user by user name
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public override async Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();
            if (userName == null)
            {
                throw new ArgumentNullException("userName");
            }
            return await Store.FindByNameAsync(userName).WithCurrentCulture();
        }

        #region 
        /// <summary>
        /// 
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        public override Task<TUser> FindByEmailAsync(string email)
        {
            //ThrowIfDisposed();
            //if (email == null)
            //{
            //    throw new ArgumentNullException("email");
            //}

            //var emailStore = Store as Framework.IUserEmailStore<TUser, TKey>;
            //if (email == null)
            //{
            //    throw new ArgumentNullException("email");
            //}
            //return  emailStore.FindByEmailAsync(email);
            throw new NotImplementedException();
        }
        #endregion

        /// <summary>
        /// 
        /// </summary>
        /// <param name="login"></param>
        /// <returns></returns>
        public override async Task<TUser> FindAsync(UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (SupportsUserLogin)
            {
                var loginStore = GetUserLoginStore();
                return await loginStore.FindAsync(login).WithCurrentCulture();
            }
            return null;
        }

        /// <summary>
        ///     Return a user with the specified username and password or null if there is no match.
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public override async Task<TUser> FindAsync(string userName, string password)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            var user = await FindByNameAsync(userName).WithCurrentCulture();
            if (user == null)
            {
                return null;
            }
            return await CheckPasswordAsync(user, password).WithCurrentCulture() ? user : null;
        }

        /// <summary>
        ///     Create a user with the given password
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> CreateAsync(TUser user, string password)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            var passwordStore = GetPasswordStore();
            var result = await CreateAsync(user).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            result = await CreatePasswordAsync(passwordStore, user, password).WithCurrentCulture();
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return result;
        }

        /// <summary>
        ///     Add a user password only if one does not already exist
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> AddPasswordAsync(TKey userId, string password)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }
            if (await passwordStore.HasPasswordAsync(user).WithCurrentCulture())
            {
                return new IdentityResult(R.String.Get("UserAlreadyHasPassword"));
            }
            var result = await CreatePasswordAsync(passwordStore, user, password).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Change a user password
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="userId"></param>
        /// <param name="oldPassword"></param>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> ChangePasswordAsync(TKey userId, string oldPassword, string newPassword)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }
            if (!await VerifyPasswordAsync(passwordStore, user, oldPassword).WithCurrentCulture())
            {
                return IdentityResult.Failed(R.String.Get("PasswordMismatch"));
            }
            var result = await UpdatePasswordAsync(passwordStore, user, newPassword).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Reset a user's password using a reset password token
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="token"></param>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> ResetPasswordAsync(TKey userId, string token, string newPassword)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }
            // Make sure the token is valid and the stamp matches
            if (!await VerifyUserTokenAsync(userId, "ResetPassword", token).WithCurrentCulture())
            {
                return IdentityResult.Failed(R.String.Get("InvalidToken"));
            }
            var result = await UpdatePasswordAsync(passwordStore, user, newPassword).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Returns true if the password is valid for the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public override async Task<bool> CheckPasswordAsync(TUser user, string password)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                return false;
            }

            var passwordStore = GetPasswordStore();
            return await VerifyPasswordAsync(passwordStore, user, password).WithCurrentCulture();
        }

        /// <summary>
        ///     Remove a user's password
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> RemovePasswordAsync(TKey userId)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }
            if (!await passwordStore.HasPasswordAsync(user))
            {
                return IdentityResult.Success;
            }
            var result = await RemovePasswordAsync(passwordStore, user).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Returns true if the user has a password
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public override async Task<bool> HasPasswordAsync(TKey userId)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }
            var result = await passwordStore.HasPasswordAsync(user).WithCurrentCulture();
            return result;
        }
        /*
                /// <summary>
                ///     Get a user's email
                /// </summary>
                /// <param name="userId"></param>
                /// <returns></returns>
                public override async Task<string> GetEmailAsync(TKey userId)
                {
                    ThrowIfDisposed();
                    if (SupportsUserLogin)
                    {
                        var emailStore = GetUserLoginStore();
                        var user = await FindByIdAsync(userId).WithCurrentCulture();
                        if (user == null)
                        {
                            throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
                        }
                        var logins = await emailStore.GetLoginsAsync(user).WithCurrentCulture();
                        var email = logins.SingleOrDefault(l => l.LoginProvider.Equals(IdentityTypes.Email.ToString(), StringComparison.OrdinalIgnoreCase));
                        if (email != null)
                        {
                            return email.ProviderKey;
                        }
                        //}
                        //else
                        //{
                        //    var store = GetEmailStore();
                        //    var user = await FindByIdAsync(userId).WithCurrentCulture();
                        //    if (user == null)
                        //    {
                        //        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                        //            userId));
                        //    }
                        //    return await store.GetEmailAsync(user).WithCurrentCulture();
                    }
                    return null;
                }

                /// <summary>
                ///     Set a user's email
                /// </summary>
                /// <param name="userId"></param>
                /// <param name="email"></param>
                /// <returns></returns>
                public override async Task<IdentityResult> SetEmailAsync(TKey userId, string email)
                {
                    ThrowIfDisposed();
                    if (SupportsUserLogin)
                    {
                        var emailStore = GetUserLoginStore();
                        var user = await FindByIdAsync(userId).WithCurrentCulture();
                        if (user == null)
                        {
                            throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
                        }
                        if (await emailStore.HasExternalAccountProviderAsync(user, new Framework.ExternalAccountInfo("Email", email)))
                        {
                            return IdentityResult.Failed("Email is Exists");
                        }
                        await emailStore.AddExternalAccountAsync(user, new Framework.ExternalAccountInfo("Email", email)).WithCurrentCulture();

                        await emailStore.SetEmailConfirmedAsync(user, false).WithCurrentCulture();
                        if (SupportsUserSecurityStamp)
                        {
                            var securityStampStore = GetSecurityStampStore();
                            await securityStampStore.SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
                        }
                    }
                    else
                    {
                        var emailStore = GetEmailStore();
                        var user = await FindByIdAsync(userId).WithCurrentCulture();
                        if (user == null)
                        {
                            throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
                        }
                        await emailStore.SetEmailAsync(user, email).WithCurrentCulture();
                        await emailStore.SetEmailConfirmedAsync(user, false).WithCurrentCulture();
                        if (SupportsUserSecurityStamp)
                        {
                            var securityStampStore = GetSecurityStampStore();
                            await securityStampStore.SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
                        }
                    }
                    await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
                    return IdentityResult.Success;
                }

                /// <summary>
                ///     Confirm the user's email with confirmation token
                /// </summary>
                /// <param name="userId"></param>
                /// <param name="token"></param>
                /// <returns></returns>
                public override async Task<IdentityResult> ConfirmEmailAsync(TKey userId, string token)
                {
                    ThrowIfDisposed();
                    if (SupportsExternalAccountStore)
                    {
                        var emailStore = GetExternalAccountStore();
                        var user = await FindByIdAsync(userId).WithCurrentCulture();
                        if (user == null)
                        {
                            throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
                        }
                        if (!await VerifyUserTokenAsync(userId, "Confirmation", token).WithCurrentCulture())
                        {
                            return IdentityResult.Failed(R.String.Get("InvalidToken"));
                        }
                        await emailStore.SetEmailConfirmedAsync(user, true).WithCurrentCulture();
                    }
                    else
                    {
                        var emailStore = GetEmailStore();
                        var user = await FindByIdAsync(userId).WithCurrentCulture();
                        if (user == null)
                        {
                            throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
                        }
                        if (!await VerifyUserTokenAsync(userId, "Confirmation", token).WithCurrentCulture())
                        {
                            return IdentityResult.Failed(R.String.Get("InvalidToken"));
                        }
                        await emailStore.SetEmailConfirmedAsync(user, true).WithCurrentCulture();
                    }
                    await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
                    return IdentityResult.Success;
                }

                /// <summary>
                ///     Returns true if the user's email has been confirmed
                /// </summary>
                /// <param name="userId"></param>
                /// <returns></returns>
                public override async Task<bool> IsEmailConfirmedAsync(TKey userId)
                {
                    ThrowIfDisposed();
                    if (SupportsExternalAccountStore)
                    {
                        var emailStore = GetExternalAccountStore();
                        var user = await FindByIdAsync(userId).WithCurrentCulture();
                        if (user == null)
                        {
                            throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
                        }
                        return await emailStore.GetEmailConfirmedAsync(user).WithCurrentCulture();
                    }
                    else
                    {
                        var emailStore = GetEmailStore();
                        var user = await FindByIdAsync(userId).WithCurrentCulture();
                        if (user == null)
                        {
                            throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                                userId));
                        }
                        return await emailStore.GetEmailConfirmedAsync(user).WithCurrentCulture();
                    }
                }
        */
        /// <summary>
        ///     Send an email to the user
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="subject"></param>
        /// <param name="body"></param>
        /// <returns></returns>
        public virtual async Task SendEmailAsync(string email, string subject, string body)
        {
            ThrowIfDisposed();
            if (EmailService != null)
            {
                var msg = new IdentityMessage
                {
                    Destination = email,//await GetEmailAsync(userId).WithCurrentCulture(),
                    Subject = subject,
                    Body = body,
                };
                await EmailService.SendAsync(msg).WithCurrentCulture();
            }
        }

        /*
        /// <summary>
        ///     Get a user's phoneNumber
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public override async Task<string> GetPhoneNumberAsync(TKey userId)
        {
            ThrowIfDisposed();
            if (SupportsUserLogin)
            {
                var phoneStore = GetUserLoginStore();
                var user = await FindByIdAsync(userId).WithCurrentCulture();
                if (user == null)
                {
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
                }
                var logins = await phoneStore.GetLoginsAsync(user).WithCurrentCulture();
                var phone = logins.SingleOrDefault(l => l.LoginProvider.Equals(IdentityTypes.PhoneNumber.ToString(), StringComparison.OrdinalIgnoreCase));
                if (phone != null)
                {
                    return phone.ProviderKey;
                }
                //}
                //else
                //{
                //    var phoneStore = GetPhoneNumberStore();
                //    var user = await FindByIdAsync(userId).WithCurrentCulture();
                //    if (user == null)
                //    {
                //        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                //            userId));
                //    }
                //    return await phoneStore.GetPhoneNumberAsync(user).WithCurrentCulture();
            }
            return null;
        }

        /// <summary>
        ///     Set a user's phoneNumber
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="phoneNumber"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> SetPhoneNumberAsync(TKey userId, string phoneNumber)
        {
            ThrowIfDisposed();
            if (SupportsExternalAccountStore)
            {
                var phoneStore = GetExternalAccountStore();
                var user = await FindByIdAsync(userId).WithCurrentCulture();
                if (user == null)
                {
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
                }
                if (await phoneStore.HasExternalAccountProviderAsync(user, new Framework.ExternalAccountInfo("PhoneNumber", phoneNumber)))
                {
                    return IdentityResult.Failed("PhoneNumber is Exists");
                }
                await phoneStore.AddExternalAccountAsync(user, new Framework.ExternalAccountInfo("PhoneNumber", phoneNumber)).WithCurrentCulture();
                await phoneStore.SetPhoneNumberConfirmedAsync(user, false).WithCurrentCulture();
                if (SupportsUserSecurityStamp)
                {
                    var securityStampStore = GetSecurityStampStore();
                    await securityStampStore.SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
                }
            }
            else
            {
                var phoneStore = GetPhoneNumberStore();
                var user = await FindByIdAsync(userId).WithCurrentCulture();
                if (user == null)
                {
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                        userId));
                }
                await phoneStore.SetPhoneNumberAsync(user, phoneNumber).WithCurrentCulture();
                await phoneStore.SetPhoneNumberConfirmedAsync(user, false).WithCurrentCulture();
                if (SupportsUserSecurityStamp)
                {
                    var securityStampStore = GetSecurityStampStore();
                    await securityStampStore.SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
                }
            }
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Set a user's phoneNumber with the verification token
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="phoneNumber"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> ChangePhoneNumberAsync(TKey userId, string phoneNumber, string token)
        {
            ThrowIfDisposed();
            if (SupportsExternalAccountStore)
            {
                var phoneStore = GetExternalAccountStore();
                var user = await FindByIdAsync(userId).WithCurrentCulture();
                if (user == null)
                {
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                        userId));
                }
                if (!await VerifyChangePhoneNumberTokenAsync(userId, token, phoneNumber).WithCurrentCulture())
                {
                    return IdentityResult.Failed(Resources.InvalidToken);
                }
                //await phoneStore.SetPhoneNumberAsync(user, phoneNumber).WithCurrentCulture();
                await phoneStore.SetPhoneNumberConfirmedAsync(user, true).WithCurrentCulture();
                if (SupportsUserSecurityStamp)
                {
                    var securityStampStore = GetSecurityStampStore();
                    await securityStampStore.SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
                }
            }
            else
            {
                var store = GetPhoneNumberStore();
                var user = await FindByIdAsync(userId).WithCurrentCulture();
                if (user == null)
                {
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                        userId));
                }
                if (!await VerifyChangePhoneNumberTokenAsync(userId, token, phoneNumber).WithCurrentCulture())
                {
                    return IdentityResult.Failed(Resources.InvalidToken);
                }
                await store.SetPhoneNumberAsync(user, phoneNumber).WithCurrentCulture();
                await store.SetPhoneNumberConfirmedAsync(user, true).WithCurrentCulture();
                if (SupportsUserSecurityStamp)
                {
                    var securityStampStore = GetSecurityStampStore();
                    await securityStampStore.SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
                }
            }
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Returns true if the user's phone number has been confirmed
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public override async Task<bool> IsPhoneNumberConfirmedAsync(TKey userId)
        {
            ThrowIfDisposed();
                var phoneStore = GetPhoneNumberStore();
                var user = await FindByIdAsync(userId).WithCurrentCulture();
                if (user == null)
                {
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                        userId));
                }
                return await phoneStore.GetPhoneNumberConfirmedAsync(user).WithCurrentCulture();
        }
        */
        /// <summary>
        ///     Send a user a sms message
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        public virtual async Task SendSmsAsync(string phoneNumber, string message)
        {
            ThrowIfDisposed();
            if (SmsService != null)
            {
                var msg = new IdentityMessage
                {
                    Destination = phoneNumber,//await GetPhoneNumberAsync(userId).WithCurrentCulture(),
                    Subject = "",
                    Body = message
                };
                await SmsService.SendAsync(msg).WithCurrentCulture();
            }
        }
        /*
        /// <summary>
        ///     Gets the logins for a user.
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public override async Task<IList<UserLoginInfo>> GetLoginsAsync(TKey userId)
        {
            ThrowIfDisposed();
            var loginStore = GetUserLoginStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }
            return await loginStore.GetLoginsAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Associate a login with a user
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> AddLoginAsync(TKey userId, UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            var loginStore = GetUserLoginStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }
            var existingUser = await FindAsync(login).WithCurrentCulture();
            if (existingUser != null)
            {
                return IdentityResult.Failed(R.String.Get("ExternalLoginExists"));
            }
            await loginStore.AddLoginAsync(user, login).WithCurrentCulture();
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Remove a user login
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> RemoveLoginAsync(TKey userId, UserLoginInfo login)
        {
            ThrowIfDisposed();
            var loginStore = GetUserLoginStore();
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }
            await loginStore.RemoveLoginAsync(user, login).WithCurrentCulture();
            if (SupportsUserSecurityStamp)
            {
                var securityStampStore = GetSecurityStampStore();
                await securityStampStore.SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
            }
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Get a users's claims
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public override async Task<IList<Claim>> GetClaimsAsync(TKey userId)
        {
            ThrowIfDisposed();
            var claimStore = GetUserClaimStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await claimStore.GetClaimsAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Add a user claim
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> AddClaimAsync(TKey userId, Claim claim)
        {
            ThrowIfDisposed();
            var claimStore = GetUserClaimStore();
            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            await claimStore.AddClaimAsync(user, claim).WithCurrentCulture();
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Remove a user claim
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> RemoveClaimAsync(TKey userId, Claim claim)
        {
            ThrowIfDisposed();
            var claimStore = GetUserClaimStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            await claimStore.RemoveClaimAsync(user, claim).WithCurrentCulture();
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }
        */
        /// <summary>
        ///     Returns the roles for the user
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<IEnumerable<KeyValuePair<TKey, string>>> GetUserRolesAsync(TKey userId)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }
            return await userRoleStore.GetRolesAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Remove a user from a role.
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> AddUserRoleAsync(TKey userId, TKey role)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }
            var userRoles = await userRoleStore.GetRolesAsync(user).WithCurrentCulture();
            if (userRoles.Any(r => r.Key.Equals(role)))
            {
                return new IdentityResult(R.String.Get("UserAlreadyInRole"));
            }
            await userRoleStore.AddToRoleAsync(user, role).WithCurrentCulture();
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        /// Method to add user to multiple roles
        /// </summary>
        /// <param name="userId">user id</param>
        /// <param name="roles">list of role names</param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> AddUserRoleAsync(TKey userId, params TKey[] roles)
        {
            ThrowIfDisposed();
            if (roles == null)
            {
                throw new ArgumentNullException("roles");
            }

            var userRoleStore = GetUserRoleStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }
            var userRoles = await userRoleStore.GetRolesAsync(user).WithCurrentCulture();
            foreach (var role in roles)
            {
                if (userRoles.Any(r => r.Key.Equals(role)))
                {
                    return new IdentityResult(R.String.Get("UserAlreadyInRole"));
                }
                await userRoleStore.AddToRoleAsync(user, role).WithCurrentCulture();
            }
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Remove a user from a role.
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> RemoveUserRoleAsync(TKey userId, TKey role)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }
            if (!await userRoleStore.IsInRoleAsync(user, role).WithCurrentCulture())
            {
                return new IdentityResult(R.String.Get("UserNotInRole"));
            }
            await userRoleStore.RemoveFromRoleAsync(user, role).WithCurrentCulture();
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        /// Remove user from multiple roles
        /// </summary>
        /// <param name="userId">user id</param>
        /// <param name="roles">list of role names</param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> RemoveUserRoleAsync(TKey userId, params TKey[] roles)
        {
            ThrowIfDisposed();
            if (roles == null)
            {
                throw new ArgumentNullException("roles");
            }

            var userRoleStore = GetUserRoleStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }

            // Remove user to each role using UserRoleStore
            var userRoles = await userRoleStore.GetRolesAsync(user).WithCurrentCulture();
            foreach (var role in roles)
            {
                if (!userRoles.Any(r => r.Key.Equals(role)))
                {
                    return new IdentityResult(R.String.Get("UserNotInRole"));
                }
                await userRoleStore.RemoveFromRoleAsync(user, role).WithCurrentCulture();
            }
            await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Returns true if the user is in the specified role
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        public virtual async Task<bool> IsInRoleAsync(TKey userId, TKey role)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, R.String.Get("UserIdNotFound"), userId));
            }
            return await userRoleStore.IsInRoleAsync(user, role).WithCurrentCulture();
        }
        /*
                /// <summary>
                ///     Returns the current security stamp for a user
                /// </summary>
                /// <param name="userId"></param>
                /// <returns></returns>
                public override async Task<string> GetSecurityStampAsync(TKey userId)
                {
                    ThrowIfDisposed();
                    var securityStampStore = GetSecurityStampStore();
                    var user = await FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                            userId));
                    }
                    return await securityStampStore.GetSecurityStampAsync(user).WithCurrentCulture();
                }

                /// <summary>
                ///     Generate a new security stamp for a user, used for SignOutEverywhere functionality
                /// </summary>
                /// <param name="userId"></param>
                /// <returns></returns>
                public override async Task<IdentityResult> UpdateSecurityStampAsync(TKey userId)
                {
                    ThrowIfDisposed();
                    var securityStampStore = GetSecurityStampStore();
                    var user = await FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                            userId));
                    }
                    await securityStampStore.SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
                    await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
                    return IdentityResult.Success;
                }*/
        /*
                /// <summary>
                ///     Get whether two factor authentication is enabled for a user
                /// </summary>
                /// <param name="userId"></param>
                /// <returns></returns>
                public override async Task<bool> GetTwoFactorEnabledAsync(TKey userId)
                {
                    ThrowIfDisposed();
                    var store = GetUserTwoFactorStore();
                    var user = await FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                            userId));
                    }
                    return await store.GetTwoFactorEnabledAsync(user).WithCurrentCulture();
                }

                /// <summary>
                ///     Set whether a user has two factor authentication enabled
                /// </summary>
                /// <param name="userId"></param>
                /// <param name="enabled"></param>
                /// <returns></returns>
                public override async Task<IdentityResult> SetTwoFactorEnabledAsync(TKey userId, bool enabled)
                {
                    ThrowIfDisposed();
                    var store = GetUserTwoFactorStore();
                    var user = await FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                            userId));
                    }
                    await store.SetTwoFactorEnabledAsync(user, enabled).WithCurrentCulture();
                    if (SupportsUserSecurityStamp)
                    {
                        var securityStampStore = GetSecurityStampStore();
                        await securityStampStore.SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
                    }
                    await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
                    return IdentityResult.Success;
                }

                /// <summary>
                ///     Returns true if the user is locked out
                /// </summary>
                /// <param name="userId"></param>
                /// <returns></returns>
                public override async Task<bool> IsLockedOutAsync(TKey userId)
                {
                    ThrowIfDisposed();
                    var lockoutStore = GetUserLockoutStore();
                    var user = await FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                            userId));
                    }
                    if (!await lockoutStore.GetLockoutEnabledAsync(user).WithCurrentCulture())
                    {
                        return false;
                    }
                    var lockoutTime = await lockoutStore.GetLockoutEndDateAsync(user).WithCurrentCulture();
                    return lockoutTime >= DateTimeOffset.UtcNow;
                }

                /// <summary>
                ///     Returns whether lockout is enabled for the user
                /// </summary>
                /// <param name="userId"></param>
                /// <returns></returns>
                public override async Task<bool> GetLockoutEnabledAsync(TKey userId)
                {
                    ThrowIfDisposed();
                    var lockoutStore = GetUserLockoutStore();
                    var user = await FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                            userId));
                    }
                    return await lockoutStore.GetLockoutEnabledAsync(user).WithCurrentCulture();
                }

                /// <summary>
                ///     Sets whether lockout is enabled for this user
                /// </summary>
                /// <param name="userId"></param>
                /// <param name="enabled"></param>
                /// <returns></returns>
                public override async Task<IdentityResult> SetLockoutEnabledAsync(TKey userId, bool enabled)
                {
                    ThrowIfDisposed();
                    var lockoutStore = GetUserLockoutStore();
                    var user = await FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                            userId));
                    }
                    await lockoutStore.SetLockoutEnabledAsync(user, enabled).WithCurrentCulture();
                    await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
                    return IdentityResult.Success;
                }

                /// <summary>
                ///     Returns when the user is no longer locked out, dates in the past are considered as not being locked out
                /// </summary>
                /// <param name="userId"></param>
                /// <returns></returns>
                public override async Task<DateTimeOffset> GetLockoutEndDateAsync(TKey userId)
                {
                    ThrowIfDisposed();
                    var lockoutStore = GetUserLockoutStore();
                    var user = await FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                            userId));
                    }
                    return await lockoutStore.GetLockoutEndDateAsync(user).WithCurrentCulture();
                }

                /// <summary>
                ///     Sets the when a user lockout ends
                /// </summary>
                /// <param name="userId"></param>
                /// <param name="lockoutEnd"></param>
                /// <returns></returns>
                public override async Task<IdentityResult> SetLockoutEndDateAsync(TKey userId, DateTimeOffset lockoutEnd)
                {
                    ThrowIfDisposed();
                    var lockoutStore = GetUserLockoutStore();
                    var user = await FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                            userId));
                    }
                    if (!await lockoutStore.GetLockoutEnabledAsync(user).WithCurrentCulture())
                    {
                        return IdentityResult.Failed(Resources.LockoutNotEnabled);
                    }
                    await lockoutStore.SetLockoutEndDateAsync(user, lockoutEnd).WithCurrentCulture();
                    await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
                    return IdentityResult.Success;
                }

                /// <summary>
                ///     Returns the number of failed access attempts for the user
                /// </summary>
                /// <param name="userId"></param>
                /// <returns></returns>
                public override async Task<int> GetAccessFailedCountAsync(TKey userId)
                {
                    ThrowIfDisposed();
                    var lockoutStore = GetUserLockoutStore();
                    var user = await FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                            userId));
                    }
                    return await lockoutStore.GetAccessFailedCountAsync(user).WithCurrentCulture();
                }

                /// <summary>
                /// Increments the access failed count for the user and if the failed access account is greater than or equal
                /// to the MaxFailedAccessAttempsBeforeLockout, the user will be locked out for the next DefaultAccountLockoutTimeSpan
                /// and the AccessFailedCount will be reset to 0. This is used for locking out the user account.
                /// </summary>
                /// <param name="userId"></param>
                /// <returns></returns>
                public override async Task<IdentityResult> AccessFailedAsync(TKey userId)
                {
                    ThrowIfDisposed();
                    var lockoutStore = GetUserLockoutStore();
                    var user = await FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                            userId));
                    }
                    // If this puts the user over the threshold for lockout, lock them out and reset the access failed count
                    var count = await lockoutStore.IncrementAccessFailedCountAsync(user).WithCurrentCulture();
                    if (count >= MaxFailedAccessAttemptsBeforeLockout)
                    {
                        await lockoutStore.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.Add(DefaultAccountLockoutTimeSpan)).WithCurrentCulture();
                        await lockoutStore.ResetAccessFailedCountAsync(user).WithCurrentCulture();
                    }
                    await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
                    return IdentityResult.Success;
                }

                /// <summary>
                ///     Resets the access failed count for the user to 0
                /// </summary>
                /// <param name="userId"></param>
                /// <returns></returns>
                public override async Task<IdentityResult> ResetAccessFailedCountAsync(TKey userId)
                {
                    ThrowIfDisposed();
                    var lockoutStore = GetUserLockoutStore();
                    var user = await FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                            userId));
                    }

                    if (await GetAccessFailedCountAsync(user.Id).WithCurrentCulture() == 0)
                    {
                        return IdentityResult.Success;
                    }
                    await lockoutStore.ResetAccessFailedCountAsync(user).WithCurrentCulture();
                    await GetTransactionStore().CommitChangesAsync().WithCurrentCulture();
                    return IdentityResult.Success;
                }
                */
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        #region Obsolete
        [Obsolete("", true)]
        protected override async Task<IdentityResult> UpdatePassword(IUserPasswordStore<TUser, TKey> passwordStore, TUser user, string newPassword)
        {
            return await Task.FromResult<IdentityResult>(null);
        }
        [Obsolete("", true)]
        protected override async Task<bool> VerifyPasswordAsync(IUserPasswordStore<TUser, TKey> store, TUser user, string password)
        {
            return await Task.FromResult<bool>(false);
        }
        [Obsolete("", true)]
        public override async Task<IList<string>> GetRolesAsync(TKey userId)
        {
            return await Task.FromResult<IList<string>>(null);
        }
        [Obsolete("", true)]
        public override async Task<IdentityResult> AddToRoleAsync(TKey userId, string role)
        {
            return await Task.FromResult<IdentityResult>(null);
        }
        [Obsolete("", true)]
        public override async Task<IdentityResult> AddToRolesAsync(TKey userId, params string[] roles)
        {
            return await Task.FromResult<IdentityResult>(null);
        }
        [Obsolete("", true)]
        public override async Task<IdentityResult> RemoveFromRoleAsync(TKey userId, string role)
        {
            return await Task.FromResult<IdentityResult>(null);
        }
        [Obsolete("", true)]
        public override async Task<IdentityResult> RemoveFromRolesAsync(TKey userId, params string[] roles)
        {
            return await Task.FromResult<IdentityResult>(null);
        }
        [Obsolete("", true)]
        public override async Task<bool> IsInRoleAsync(TKey userId, string role)
        {
            return await Task.FromResult<bool>(false);
        }
        [Obsolete("", true)]
        public override async Task SendEmailAsync(TKey userId, string subject, string body)
        {
            await Task.FromResult(0);
        }
        [Obsolete("", true)]
        public override async Task SendSmsAsync(TKey userId, string message)
        {
            await Task.FromResult(0);
        }
        #endregion

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /*
        /// <summary>
        ///     Get a user token for a specific purpose
        /// </summary>
        /// <param name="purpose"></param>
        /// <param name="userId"></param>
        /// <returns></returns>
        public override async Task<string> GenerateUserTokenAsync(string purpose, TKey userId)
        {
            ThrowIfDisposed();
            if (UserTokenProvider == null)
            {
                throw new NotSupportedException(Resources.NoTokenProvider);
            }
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await UserTokenProvider.GenerateAsync(purpose, this, user).WithCurrentCulture();
        }

        /// <summary>
        ///     Verify a user token with the specified purpose
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="purpose"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        public override async Task<bool> VerifyUserTokenAsync(TKey userId, string purpose, string token)
        {
            ThrowIfDisposed();
            if (UserTokenProvider == null)
            {
                throw new NotSupportedException(Resources.NoTokenProvider);
            }
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            // Make sure the token is valid
            return await UserTokenProvider.ValidateAsync(purpose, token, this, user).WithCurrentCulture();
        }

        /// <summary>
        ///     Generate a password reset token for the user using the UserTokenProvider
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public override Task<string> GeneratePasswordResetTokenAsync(TKey userId)
        {
            ThrowIfDisposed();
            return GenerateUserTokenAsync("ResetPassword", userId);
        }

        /// <summary>
        ///     Get the email confirmation token for the user
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public override Task<string> GenerateEmailConfirmationTokenAsync(TKey userId)
        {
            ThrowIfDisposed();
            return GenerateUserTokenAsync("Confirmation", userId);
        }

        /// <summary>
        ///     Generate a code that the user can use to change their phone number to a specific number
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="phoneNumber"></param>
        /// <returns></returns>
        public override async Task<string> GenerateChangePhoneNumberTokenAsync(TKey userId, string phoneNumber)
        {
            ThrowIfDisposed();
            return Rfc6238AuthenticationService.GenerateCode(await CreateSecurityTokenAsync(userId).WithCurrentCulture(), phoneNumber)
                    .ToString("D6", CultureInfo.InvariantCulture);
        }

        /// <summary>
        ///     Verify the code is valid for a specific user and for a specific phone number
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="token"></param>
        /// <param name="phoneNumber"></param>
        /// <returns></returns>
        public override async Task<bool> VerifyChangePhoneNumberTokenAsync(TKey userId, string token, string phoneNumber)
        {
            ThrowIfDisposed();
            var securityToken = await CreateSecurityTokenAsync(userId).WithCurrentCulture();
            int code;
            if (securityToken != null && Int32.TryParse(token, out code))
            {
                return Rfc6238AuthenticationService.ValidateCode(securityToken, code, phoneNumber);
            }
            return false;
        }

        /// <summary>
        ///     Register a two factor authentication provider with the TwoFactorProviders mapping
        /// </summary>
        /// <param name="twoFactorProvider"></param>
        /// <param name="provider"></param>
        public override void RegisterTwoFactorProvider(string twoFactorProvider, IUserTokenProvider<TUser, TKey> provider)
        {
            ThrowIfDisposed();
            if (twoFactorProvider == null)
            {
                throw new ArgumentNullException("twoFactorProvider");
            }
            if (provider == null)
            {
                throw new ArgumentNullException("provider");
            }
            TwoFactorProviders[twoFactorProvider] = provider;
        }

        /// <summary>
        ///     Returns a list of valid two factor providers for a user
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public override async Task<IList<string>> GetValidTwoFactorProvidersAsync(TKey userId)
        {
            ThrowIfDisposed();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            var results = new List<string>();
            foreach (var f in TwoFactorProviders)
            {
                if (await f.Value.IsValidProviderForUserAsync(this, user).WithCurrentCulture())
                {
                    results.Add(f.Key);
                }
            }
            return results;
        }
        */
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        // Two factor APIS

        //internal async Task<SecurityToken> CreateSecurityTokenAsync(TKey userId)
        //{
        //    return new SecurityToken(Encoding.Unicode.GetBytes(await GetSecurityStampAsync(userId).WithCurrentCulture()));
        //}

        /// <summary>
        /// 
        /// </summary>
        /// <param name="store"></param>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        internal async Task<IdentityResult> CreatePasswordAsync(Microsoft.AspNet.Identity.Framework.IUserPasswordStore<TUser, TKey> store, TUser user, string password)
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
            return IdentityResult.Success;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="store"></param>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        internal async Task<IdentityResult> UpdatePasswordAsync(Microsoft.AspNet.Identity.Framework.IUserPasswordStore<TUser, TKey> store, TUser user, string password)
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
            await store.SetPasswordHashAsync(user, passwordHash, salt).WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="store"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        internal async Task<IdentityResult> RemovePasswordAsync(Microsoft.AspNet.Identity.Framework.IUserPasswordStore<TUser, TKey> store, TUser user)
        {
            if (SupportsUserSecurityStamp)
            {
                var securityStampStore = GetSecurityStampStore();
                await securityStampStore.SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
            }
            await store.SetPasswordHashAsync(user, null, null).WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="store"></param>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        internal async Task<bool> VerifyPasswordAsync(Microsoft.AspNet.Identity.Framework.IUserPasswordStore<TUser, TKey> store, TUser user, string password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return false;
            }

            if (!await store.HasPasswordAsync(user).WithCurrentCulture())
            {
                return false;
            }
            var srcHash = PasswordHasher.HashPassword(password);
            var destHash = srcHash;
            var salt = await store.GetHashKeyAsync(user);
            var passwordHash = Framework.Crypto.Encrypt(destHash, salt);
            return await store.VerifyPasswordAsync(user, passwordHash);
        }

        /// ///////////////////////////////////////////////////////////////////////////////////////
        //
        private static string NewSecurityStamp()
        {
            return Guid.NewGuid().ToString("N");
        }

        //IUserPasswordStore methods
        private Framework.IUserPasswordStore<TUser, TKey> GetPasswordStore()
        {
            var cast = Store as Framework.IUserPasswordStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(R.String.Get("StoreNotIUserPasswordStore"));
            }
            return cast;
        }

        // IUserSecurityStampStore methods
        private IUserSecurityStampStore<TUser, TKey> GetSecurityStampStore()
        {
            var cast = Store as IUserSecurityStampStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(R.String.Get("StoreNotIUserSecurityStampStore"));
            }
            return cast;
        }

        // IUserRoleStore methods
        private Framework.IUserRoleStore<TUser, TKey> GetUserRoleStore()
        {
            var cast = Store as Framework.IUserRoleStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(R.String.Get("StoreNotIUserRoleStore"));
            }
            return cast;
        }

        // IUserLoginStore methods
        private IUserLoginStore<TUser, TKey> GetUserLoginStore()
        {
            var cast = Store as IUserLoginStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(R.String.Get("StoreNotIUserLoginStore"));
            }
            return cast;
        }

        // IUserLockoutStore methods
        private IUserLockoutStore<TUser, TKey> GetUserLockoutStore()
        {
            var cast = Store as IUserLockoutStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(R.String.Get("StoreNotIUserLockoutStore"));
            }
            return cast;
        }

        /*
        // IUserPhoneNumberStore methods
        internal IUserPhoneNumberStore<TUser, TKey> GetPhoneNumberStore()
        {
            var cast = Store as IUserPhoneNumberStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserPhoneNumberStore);
            }
            return cast;
        }
        
        // IUserEmailStore methods
        internal IUserEmailStore<TUser, TKey> GetEmailStore()
        {
            var cast = Store as IUserEmailStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserEmailStore);
            }
            return cast;
        }


        // IUserClaimStore methods
        private IUserClaimStore<TUser, TKey> GetUserClaimStore()
        {
            var cast = Store as IUserClaimStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserClaimStore);
            }
            return cast;
        }

        // IUserFactorStore methods
        private IUserTwoFactorStore<TUser, TKey> GetUserTwoFactorStore()
        {
            var cast = Store as IUserTwoFactorStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserTwoFactorStore);
            }
            return cast;
        }
        */
        // ITransactionStore methods
        private Framework.ITransactionStore<TUser, TKey> GetTransactionStore()
        {
            var cast = Store as Framework.ITransactionStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(R.String.Get("StoreNotITransactionStore"));
            }
            return cast;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////
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
        protected override void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                //Store.Dispose();
                base.Dispose(disposing);
                _disposed = true;
            }
        }

        /// <summary>
        ///     Dispose the store
        /// </summary>
        //public void Dispose()
        //{
        //    Dispose(true);
        //    GC.SuppressFinalize(this);
        //}
    }
}
