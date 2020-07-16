using System.Threading.Tasks;

namespace Microsoft.Identity
{
    /// <summary>
    ///     Stores a user's password hash
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public interface IUserPasswordStore<TUser> : IUserPasswordStore<TUser, string> where TUser : class, IUser<string>
    {
    }

    /// <summary>
    ///     Stores a user's password hash
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public interface IUserPasswordStore<TUser, in TKey> : IUserStore<TUser, TKey> where TUser : class, IUser<TKey>
    {
        /// <summary>
        ///     Set the user password hash
        /// </summary>
        /// <param name="user"></param>
        /// <param name="passwordHash"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        Task SetPasswordHashAsync(TUser user, string passwordHash, string privateKey);

        /// <summary>
        ///     Verify the user password hash
        /// </summary>
        /// <param name="user"></param>
        /// <param name="passwordHash"></param>
        /// <returns></returns>
        Task<bool> VerifyPasswordAsync(TUser user, string passwordHash);

        /// <summary>
        ///     Returns true if a user has a password set
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        Task<bool> HasPasswordAsync(TUser user);

        /// <summary>
        ///     Get the user private hash
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        Task<string> GetPrivateKeyAsync(TUser user);
    }
}