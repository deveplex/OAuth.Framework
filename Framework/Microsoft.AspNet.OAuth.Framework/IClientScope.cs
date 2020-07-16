
namespace Microsoft.AspNet.OAuth
{
    public interface IClientScope : IClientScope<string>
    {
    }

    public interface IClientScope<TKey>
    {
        string ClientId { get; set; }

        string ScopeId { get; set; }
    }
}
