using System.ComponentModel.Composition;

namespace Microsoft.AspNet.Identity.Security.Providers
{
    [InheritedExport]
    public interface IHashProvider
    {
        string Hash(string source);
    }
}
