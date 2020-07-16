
namespace Microsoft.AspNet.Identity
{
    public interface IUserRole : IUserRole<string>
    {
    }

    /// <summary>
    ///     EntityType that represents a user belonging to a role
    /// </summary>
    /// <typeparam name="TKey"></typeparam>
    public interface IUserRole<TKey>
    {
        /// <summary>
        ///     UserId for the user that is in the role
        /// </summary>
        TKey UserId { get; set; }

        /// <summary>
        ///     RoleId for the role
        /// </summary>
        TKey RoleId { get; set; }
    }
}