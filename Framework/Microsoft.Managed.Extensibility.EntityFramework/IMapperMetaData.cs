using System;

namespace Microsoft.Managed.Extensibility.EntityFramework
{
    public interface IMapperMetaData
    {
        string Catalog { get; }
        string ContractName { get; }
        Type ContractType { get; }
    }
}
