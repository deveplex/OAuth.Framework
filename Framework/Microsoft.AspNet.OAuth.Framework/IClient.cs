using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.OAuth
{
    public interface IClient : IClient<string>
    {
    }

    public interface IClient<TKey>
    {
        TKey Id { get; set; }

        string ClientName { get; set; }
    }
}
