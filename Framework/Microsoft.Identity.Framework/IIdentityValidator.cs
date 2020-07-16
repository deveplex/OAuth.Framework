using System.Net;
using System.Threading.Tasks;

namespace Microsoft.Identity
{
    /// <summary>
    ///     Used to validate an item
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public interface IIdentityValidator<in T>
    {
        /// <summary>
        ///     Validate the item
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        Task<IdentityResult> ValidateAsync(T item);
    }
}