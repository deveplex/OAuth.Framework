using Microsoft.Managed.Extensibility.EntityFramework;
using System.ComponentModel.Composition;
using System.Data.Entity.ModelConfiguration.Configuration;

namespace Microsoft.Managed.Extensibility.EntityFramework
{
    /// <summary>  
    /// 实体映射接口  
    /// </summary>  
    [InheritedExport]
    public interface IEntityConfigurationMapper
    {
        IMapperMetaData MapperMetaData { get; }

        /// <summary>  
        /// 将当前实体映射对象注册到当前数据访问上下文实体映射配置注册器中  
        /// </summary>  
        /// <param name="configurations">实体映射配置注册器</param>  
        void Register(ConfigurationRegistrar configurations);
    }
}
