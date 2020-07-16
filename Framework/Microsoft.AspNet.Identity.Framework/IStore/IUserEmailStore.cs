using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity.Framework
{
    public interface IUserEmailStore<TUser, in TKey> : IUserStore<TUser, TKey>, IDisposable where TUser : class, IUser<TKey>
    {
        Task<string> GetEmailAsync(TUser user);
        Task<bool> GetEmailConfirmedAsync(TUser user);
        Task SetEmailAsync(TUser user, string email);
        Task SetEmailConfirmedAsync(TUser user, bool confirmed);
    }
}