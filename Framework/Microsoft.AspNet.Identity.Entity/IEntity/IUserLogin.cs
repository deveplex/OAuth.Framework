
namespace Microsoft.AspNet.Identity
{
    public interface IUserLogin : IUserLogin<string>
    {
    }

    /// <summary>
    ///     Entity type for a user's login (i.e. facebook, google)
    /// </summary>
    /// <typeparam name="TKey"></typeparam>
    public interface IUserLogin<TKey>
    {
        /// <summary>
        ///     User Id for the user who owns this login
        /// </summary>
        TKey UserId { get; set; }

        /// <summary>
        ///     The login provider for the login (i.e. facebook, google)
        /// </summary>
        string LoginProvider { get; set; }

        /// <summary>
        ///     Key representing the login for the provider
        /// </summary>
        string ProviderKey { get; set; }
    }
}