using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
namespace Microsoft.AspNet.Identity
{
    public static class UserManagerExtensions
    {
        /*
                /// <summary>
                ///     Create a user with the given password
                /// </summary>
                /// <param name="user"></param>
                /// <param name="password"></param>
                /// <returns></returns>
                public static async Task<IdentityResult> CreateUserAsync<TUser, TKey>(this UserManager<TUser, TKey> manager, TUser user, string password)
                    where TUser : class, IUser<TKey>
                    where TKey : IEquatable<TKey>
                {
                    if (manager == null)
                    {
                        throw new ArgumentNullException("manager");
                    }
                    if (user == null)
                    {
                        throw new ArgumentNullException("user");
                    }
                    if (password == null)
                    {
                        throw new ArgumentNullException("password");
                    }

                    var passwordStore = GetPasswordStore(manager);
                    var result = await manager.CreatePasswordAsync(passwordStore, user, password).WithCurrentCulture();
                    if (!result.Succeeded)
                    {
                        return result;
                    }
                    return await manager.CreateAsync(user).WithCurrentCulture();
                }

                /// <summary>
                ///     Return a user with the specified username and password or null if there is no match.
                /// </summary>
                /// <param name="userName"></param>
                /// <param name="password"></param>
                /// <returns></returns>
                public static async Task<TUser> FindUserAsync<TUser, TKey>(this UserManager<TUser, TKey> manager, string userName, string password)
                    where TUser : class, IUser<TKey>
                    where TKey : IEquatable<TKey>
                {
                    if (manager == null)
                    {
                        throw new ArgumentNullException("manager");
                    }

                    var user = await manager.FindByNameAsync(userName).WithCurrentCulture();
                    if (user == null)
                    {
                        return null;
                    }

                    var passwordStore = GetPasswordStore(manager);
                    return await manager.VerifyPasswordAsync(passwordStore, user, password).WithCurrentCulture() ? user : null;
                }

                ///// <summary>
                /////     Change a user password
                ///// </summary>
                ///// <param name="manager"></param>
                ///// <param name="userId"></param>
                ///// <param name="password"></param>
                ///// <returns></returns>
                //public static async Task<IdentityResult> CreateUserPasswordAsync<TUser, TKey>(this UserManager<TUser, TKey> manager, TKey userId, string password)
                //    where TUser : class, IUser<TKey>
                //    where TKey : IEquatable<TKey>
                //{
                //    if (manager == null)
                //    {
                //        throw new ArgumentNullException("manager");
                //    }

                //    var user = await manager.FindByIdAsync(userId).WithCurrentCulture();
                //    if (user == null)
                //    {
                //        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                //            "UserId Not Found", userId));
                //    }
                //    var passwordStore = GetPasswordStore(manager);
                //    var result = await manager.CreatePasswordAsync(passwordStore, user, password).WithCurrentCulture();
                //    if (!result.Succeeded)
                //    {
                //        return result;
                //    }
                //    return await manager.UpdateAsync(user).WithCurrentCulture();
                //}

                /// <summary>
                ///     Change a user password
                /// </summary>
                /// <param name="manager"></param>
                /// <param name="userId"></param>
                /// <param name="oldPassword"></param>
                /// <param name="newPassword"></param>
                /// <returns></returns>
                public static async Task<IdentityResult> ChangeUserPasswordAsync<TUser, TKey>(this UserManager<TUser, TKey> manager, TKey userId, string oldPassword, string newPassword)
                    where TUser : class, IUser<TKey>
                    where TKey : IEquatable<TKey>
                {
                    if (manager == null)
                    {
                        throw new ArgumentNullException("manager");
                    }

                    var user = await manager.FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                            "UserId Not Found", userId));
                    }
                    var passwordStore = GetPasswordStore(manager);
                    if (!await manager.VerifyPasswordAsync(passwordStore, user, oldPassword).WithCurrentCulture())
                    {
                        return IdentityResult.Failed("Password Mismatch");
                    }
                    var result = await manager.UpdatePasswordAsync(passwordStore, user, newPassword).WithCurrentCulture();
                    if (!result.Succeeded)
                    {
                        return result;
                    }
                    return await manager.UpdateAsync(user).WithCurrentCulture();
                }

                /// <summary>
                ///     Reset a user's password using a reset password token
                /// </summary>
                /// <param name="userId"></param>
                /// <param name="token"></param>
                /// <param name="newPassword"></param>
                /// <returns></returns>
                public static async Task<IdentityResult> ResetUserPasswordAsync<TUser, TKey>(this UserManager<TUser, TKey> manager, TKey userId, string token, string newPassword)
                    where TUser : class, IUser<TKey>
                    where TKey : IEquatable<TKey>
                {
                    if (manager == null)
                    {
                        throw new ArgumentNullException("manager");
                    }

                    var user = await manager.FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                            "UserId Not Found", userId));
                    }
                    // Make sure the token is valid and the stamp matches
                    if (!await manager.VerifyUserTokenAsync(userId, "ResetPassword", token).WithCurrentCulture())
                    {
                        return IdentityResult.Failed("Invalid Token");
                    }
                    var passwordStore = GetPasswordStore(manager);
                    var result = await manager.UpdatePasswordAsync(passwordStore, user, newPassword).WithCurrentCulture();
                    if (!result.Succeeded)
                    {
                        return result;
                    }
                    return await manager.UpdateAsync(user).WithCurrentCulture();
                }

                /// <summary>
                ///     Returns true if the password is valid for the user
                /// </summary>
                /// <param name="user"></param>
                /// <param name="password"></param>
                /// <returns></returns>
                public static async Task<bool> CheckUserPasswordAsync<TUser, TKey>(this UserManager<TUser, TKey> manager, TUser user, string password)
                    where TUser : class, IUser<TKey>
                    where TKey : IEquatable<TKey>
                {
                    if (manager == null)
                    {
                        throw new ArgumentNullException("manager");
                    }
                    if (user == null)
                    {
                        return false;
                    }

                    var passwordStore = GetPasswordStore(manager);
                    return await manager.VerifyPasswordAsync(passwordStore, user, password).WithCurrentCulture();
                }

                /// <summary>
                ///     Returns the roles for the user
                /// </summary>
                /// <param name="userId"></param>
                /// <returns></returns>
                public static async Task<IList<TRole>> GetUserRolesAsync<TUser, TKey, TRole>(this UserManager<TUser, TKey> manager, TKey userId)
                    where TUser : class, IUser<TKey>
                    where TRole : class, IRole<TKey>
                    where TKey : IEquatable<TKey>
                {
                    if (manager == null)
                    {
                        throw new ArgumentNullException("manager");
                    }

                    var user = await manager.FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                            "UserId Not Found", userId));
                    }

                    var userRoleStore = GetUserRoleStore<TUser, TKey, TRole>(manager);
                    return await userRoleStore.GetRolesAsync(user).WithCurrentCulture();
                }

                /// <summary>
                ///     Remove a user from a role.
                /// </summary>
                /// <param name="userId"></param>
                /// <param name="role"></param>
                /// <returns></returns>
                public static async Task<IdentityResult> AddUserRoleAsync<TUser, TKey, TRole>(this UserManager<TUser, TKey> manager, TKey userId, TRole role)
                    where TUser : class, IUser<TKey>
                    where TRole : class, IRole<TKey>
                    where TKey : IEquatable<TKey>
                {
                    if (manager == null)
                    {
                        throw new ArgumentNullException("manager");
                    }
                    if (role == null)
                    {
                        throw new ArgumentNullException("role");
                    }

                    var user = await manager.FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                            "UserId Not Found", userId));
                    }
                    var userRoleStore = GetUserRoleStore<TUser, TKey, TRole>(manager);
                    var userRoles = await userRoleStore.GetRolesAsync(user).WithCurrentCulture();
                    if (userRoles.Contains(role))
                    {
                        return new IdentityResult("UserAlreadyInRole");
                    }
                    await userRoleStore.AddToRoleAsync(user, role).WithCurrentCulture();

                    return await manager.UpdateAsync(user).WithCurrentCulture();
                }

                /// <summary>
                /// Method to add user to multiple roles
                /// </summary>
                /// <param name="userId">user id</param>
                /// <param name="roles">list of role names</param>
                /// <returns></returns>
                public static async Task<IdentityResult> AddUserRoleAsync<TUser, TKey, TRole>(this UserManager<TUser, TKey> manager, TKey userId, TRole[] roles)
                    where TUser : class, IUser<TKey>
                    where TRole : class, IRole<TKey>
                    where TKey : IEquatable<TKey>
                {
                    if (manager == null)
                    {
                        throw new ArgumentNullException("manager");
                    }
                    if (roles == null)
                    {
                        throw new ArgumentNullException("roles");
                    }


                    var user = await manager.FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                            "UserId Not Found", userId));
                    }
                    var userRoleStore = GetUserRoleStore<TUser, TKey, TRole>(manager);
                    var userRoles = await userRoleStore.GetRolesAsync(user).WithCurrentCulture();
                    foreach (var r in roles)
                    {
                        if (userRoles.Contains(r))
                        {
                            return new IdentityResult("UserAlreadyInRole");
                        }
                        await userRoleStore.AddToRoleAsync(user, r).WithCurrentCulture();
                    }

                    return await manager.UpdateAsync(user).WithCurrentCulture();
                }

                /// <summary>
                ///     Remove a user from a role.
                /// </summary>
                /// <param name="userId"></param>
                /// <param name="role"></param>
                /// <returns></returns>
                public static async Task<IdentityResult> RemoveUserRoleAsync<TUser, TKey, TRole>(this UserManager<TUser, TKey> manager, TKey userId, TRole role)
                    where TUser : class, IUser<TKey>
                    where TRole : class, IRole<TKey>
                    where TKey : IEquatable<TKey>
                {
                    if (manager == null)
                    {
                        throw new ArgumentNullException("manager");
                    }
                    if (role == null)
                    {
                        throw new ArgumentNullException("role");
                    }

                    var user = await manager.FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                            "UserId Not Found", userId));
                    }
                    var userRoleStore = GetUserRoleStore<TUser, TKey, TRole>(manager);
                    if (!await userRoleStore.IsInRoleAsync(user, role).WithCurrentCulture())
                    {
                        return new IdentityResult("UserNotInRole");
                    }
                    await userRoleStore.RemoveFromRoleAsync(user, role).WithCurrentCulture();
                    return await manager.UpdateAsync(user).WithCurrentCulture();
                }

                /// <summary>
                /// Remove user from multiple roles
                /// </summary>
                /// <param name="userId">user id</param>
                /// <param name="roles">list of role names</param>
                /// <returns></returns>
                public static async Task<IdentityResult> RemoveUserRoleAsync<TUser, TKey, TRole>(this UserManager<TUser, TKey> manager, TKey userId, TRole[] roles)
                    where TUser : class, IUser<TKey>
                    where TRole : class, IRole<TKey>
                    where TKey : IEquatable<TKey>
                {
                    if (manager == null)
                    {
                        throw new ArgumentNullException("manager");
                    }
                    if (roles == null)
                    {
                        throw new ArgumentNullException("roles");
                    }

                    var user = await manager.FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                            "UserId Not Found", userId));
                    }

                    var userRoleStore = GetUserRoleStore<TUser, TKey, TRole>(manager);
                    // Remove user to each role using UserRoleStore
                    var userRoles = await userRoleStore.GetRolesAsync(user).WithCurrentCulture();
                    foreach (var role in roles)
                    {
                        if (!userRoles.Contains(role))
                        {
                            return new IdentityResult("UserNotInRole");
                        }
                        await userRoleStore.RemoveFromRoleAsync(user, role).WithCurrentCulture();
                    }

                    // Call update once when all roles are removed
                    return await manager.UpdateAsync(user).WithCurrentCulture();
                }

                /// <summary>
                ///     Returns true if the user is in the specified role
                /// </summary>
                /// <param name="userId"></param>
                /// <param name="role"></param>
                /// <returns></returns>
                public static async Task<bool> IsInRoleAsync<TUser, TKey, TRole>(this UserManager<TUser, TKey> manager, TKey userId, TRole role)
                    where TUser : class, IUser<TKey>
                    where TRole : class, IRole<TKey>
                    where TKey : IEquatable<TKey>
                {
                    if (manager == null)
                    {
                        throw new ArgumentNullException("manager");
                    }
                    if (role == null)
                    {
                        throw new ArgumentNullException("roles");
                    }


                    var user = await manager.FindByIdAsync(userId).WithCurrentCulture();
                    if (user == null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture,
                            "UserId Not Found", userId));
                    }

                    var userRoleStore = GetUserRoleStore<TUser, TKey, TRole>(manager);
                    return await userRoleStore.IsInRoleAsync(user, role).WithCurrentCulture();
                }

                // Update the security stamp if the store supports it
                internal static async Task UpdateSecurityStampAsync<TUser, TKey>(this UserManager<TUser, TKey> manager, IUserSecurityStampStore<TUser, TKey> store, TUser user, string securityStamp)
                    where TKey : IEquatable<TKey>
                    where TUser : class, IUser<TKey>
                {
                    await store.SetSecurityStampAsync(user, securityStamp).WithCurrentCulture();
                }

                internal static async Task AddSecurityStampAsync<TUser, TKey>(this UserManager<TUser, TKey> manager, Microsoft.AspNet.Identity.Framework.IUserPasswordStore<TUser, TKey> store, TUser user, string securityStamp)
                    where TKey : IEquatable<TKey>
                    where TUser : class, IUser<TKey>
                {
                    await store.AddSecurityStampAsync(user, securityStamp).WithCurrentCulture();
                }

                internal static async Task<IdentityResult> CreatePasswordAsync<TUser, TKey>(this UserManager<TUser, TKey> manager, Microsoft.AspNet.Identity.Framework.IUserPasswordStore<TUser, TKey> store, TUser user, string newPassword)
                    where TKey : IEquatable<TKey>
                    where TUser : class, IUser<TKey>
                {
                    var result = await manager.PasswordValidator.ValidateAsync(newPassword).WithCurrentCulture();
                    if (!result.Succeeded)
                    {
                        return result;
                    }
                    await store.CreatePasswordAsync(user, manager.PasswordHasher.HashPassword(newPassword)).WithCurrentCulture();
                    if (manager.SupportsUserSecurityStamp)
                    {
                        var securityStampStore = GetSecurityStampStore(manager);
                        await manager.AddSecurityStampAsync(store, user, NewSecurityStamp()).WithCurrentCulture();
                    }
                    return IdentityResult.Success;
                }

                internal static async Task<IdentityResult> UpdatePasswordAsync<TUser, TKey>(this UserManager<TUser, TKey> manager, Microsoft.AspNet.Identity.Framework.IUserPasswordStore<TUser, TKey> store, TUser user, string newPassword)
                    where TKey : IEquatable<TKey>
                    where TUser : class, IUser<TKey>
                {
                    var result = await manager.PasswordValidator.ValidateAsync(newPassword).WithCurrentCulture();
                    if (!result.Succeeded)
                    {
                        return result;
                    }
                    await store.SetPasswordAsync(user, manager.PasswordHasher.HashPassword(newPassword)).WithCurrentCulture();
                    if (manager.SupportsUserSecurityStamp)
                    {
                        var securityStampStore = GetSecurityStampStore(manager);
                        await manager.UpdateSecurityStampAsync(securityStampStore, user, NewSecurityStamp()).WithCurrentCulture();
                    }
                    return IdentityResult.Success;
                }

                internal static async Task<bool> VerifyPasswordAsync<TUser, TKey>(this UserManager<TUser, TKey> manager, Microsoft.AspNet.Identity.Framework.IUserPasswordStore<TUser, TKey> store, TUser user, string password)
                    where TKey : IEquatable<TKey>
                    where TUser : class, IUser<TKey>
                {
                    //var hash = await store.GetPasswordHashAsync(user).WithCurrentCulture();
                    //return manager.PasswordHasher.VerifyHashedPassword(hash, password) != PasswordVerificationResult.Failed;

                    return await store.VerifyPasswordAsync(user, manager.PasswordHasher.HashPassword(password));
                }

                /// ///////////////////////////////////////////////////////////////////////////////////////
                private static string NewSecurityStamp()
                {
                    return Guid.NewGuid().ToString();
                }

                // IUserSecurityStampStore methods
                private static IUserSecurityStampStore<TUser, TKey> GetSecurityStampStore<TUser, TKey>(this UserManager<TUser, TKey> manager)
                    where TUser : class, IUser<TKey>
                    where TKey : IEquatable<TKey>
                {
                    var cast = manager.Store as IUserSecurityStampStore<TUser, TKey>;
                    if (cast == null)
                    {
                        throw new NotSupportedException("Store Not IUserSecurityStampStore");
                    }
                    return cast;
                }

                // IUserPasswordStore methods
                private static Microsoft.AspNet.Identity.Framework.IUserPasswordStore<TUser, TKey> GetPasswordStore<TUser, TKey>(this UserManager<TUser, TKey> manager)
                    where TUser : class, IUser<TKey>
                    where TKey : IEquatable<TKey>
                {
                    var cast = manager.Store as Microsoft.AspNet.Identity.Framework.IUserPasswordStore<TUser, TKey>;
                    if (cast == null)
                    {
                        throw new NotSupportedException("Store Not IUserPasswordStore");
                    }
                    return cast;
                }

                // IUserRoleStore methods
                private static Microsoft.AspNet.Identity.Framework.IUserRoleStore<TUser, TKey, TRole> GetUserRoleStore<TUser, TKey, TRole>(this UserManager<TUser, TKey> manager)
                    where TUser : class, IUser<TKey>
                    where TRole : class, IRole<TKey>
                    where TKey : IEquatable<TKey>
                {
                    var cast = manager.Store as Microsoft.AspNet.Identity.Framework.IUserRoleStore<TUser, TKey, TRole>;
                    if (cast == null)
                    {
                        throw new NotSupportedException("Store Not IUserRoleStore");
                    }
                    return cast;
                }
        */
    }
}
