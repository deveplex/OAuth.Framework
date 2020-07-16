using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.Identity
{
    /// <summary>
    ///     Interface that maps users to their roles
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public interface IUserRoleStore<TUser> : IUserRoleStore<TUser, string> where TUser : class, IUser<string>
    {
    }

    /// <summary>
    ///     Interface that maps users to their roles
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public interface IUserRoleStore<TUser, TKey> : IUserStore<TUser, TKey> where TUser : class, IUser<TKey>
    {
        /// <summary>
        ///     Returns the roles for this user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        Task<IEnumerable<KeyValuePair<TKey, string>>> GetRolesAsync(TUser user);

        /// <summary>
        ///     Adds a user to a role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        Task AddToRoleAsync(TUser user, TKey roleId);

        /// <summary>
        ///     Removes the role for the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        Task RemoveFromRoleAsync(TUser user, TKey roleId);

        /// <summary>
        ///     Returns true if a user is in the role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        Task<bool> IsInRoleAsync(TUser user, TKey roleId);
    }
}