using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity.Framework
{
    public interface IUserRoleStore<TUser, TKey> : IUserStore<TUser, TKey>, IDisposable 
        where TUser : class, IUser<TKey>
        where TKey : IEquatable<TKey>
    {
        Task AddToRoleAsync(TUser user, TKey roleId);
        Task<IEnumerable<KeyValuePair<TKey, string>>> GetRolesAsync(TUser user);
        Task<bool> IsInRoleAsync(TUser user, TKey roleId);
        Task RemoveFromRoleAsync(TUser user, TKey roleId);
    }
}