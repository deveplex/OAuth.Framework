using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity.Framework
{
    public interface IUserPasswordStore<TUser, in TKey> : IUserStore<TUser, TKey>, IDisposable 
        where TUser : class, IUser<TKey>
    {
        Task AddPasswordHashAsync(TUser user, string passwordHash, string privateHash);
        Task SetPasswordHashAsync(TUser user, string passwordHash, string privateHash);
        Task<bool> HasPasswordAsync(TUser user);
        Task<bool> VerifyPasswordAsync(TUser user, string passwordHash);
        Task<string> GetHashKeyAsync(TUser user);
    }
}
