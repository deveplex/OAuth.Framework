using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Identity
{
    public interface ITransactionStore<TUser, in TKey> : IUserStore<TUser, TKey>, IDisposable
        where TUser : class, IUser<TKey>
    {
        Task CommitChangesAsync();
    }
}
