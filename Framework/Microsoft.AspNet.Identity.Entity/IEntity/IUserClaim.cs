
namespace Microsoft.AspNet.Identity
{
    public interface IUserClaim : IUserClaim<string>
    {
    }

    /// <summary>
    ///     EntityType that represents one specific user claim
    /// </summary>
    /// <typeparam name="TKey"></typeparam>
    public interface IUserClaim<TKey>
    {
        /// <summary>
        ///     User Id for the user who owns this login
        /// </summary>
        TKey UserId { get; set; }

        /// <summary>
        ///     Claim type
        /// </summary>
        string ClaimType { get; set; }

        /// <summary>
        ///     Claim value
        /// </summary>
        string ClaimValue { get; set; }
    }
}