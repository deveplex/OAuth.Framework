using GMF.Demo.Site.Helper.Ioc;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition.Hosting;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace OAuthServer.Test
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            GlobalConfiguration.Configure(WebApiConfig.Register);

            JsonConvert.DefaultSettings = new Func<JsonSerializerSettings>(() =>
            {
                JsonSerializerSettings setting = new JsonSerializerSettings();
                setting.Formatting = Formatting.Indented;

                //日期类型默认格式化处理
                setting.DateFormatHandling = Newtonsoft.Json.DateFormatHandling.MicrosoftDateFormat;
                setting.DateFormatString = "yyyy-MM-dd HH:mm:ss";
                setting.Converters.Add(new UniversalDateTimeConverter());

                //空值处理
                setting.NullValueHandling = NullValueHandling.Ignore;

                //高级用法九中的Bool类型转换 设置
                //setting.Converters.Add(new BoolConvert("是,否"));

                //if (setting.Converters.FirstOrDefault(p => p.GetType() == typeof(JsonCustomDoubleConvert)) == null)
                //{
                //    setting.Converters.Add(new JsonCustomDoubleConvert(3));
                //}

                return setting;
            });

            //var catalog = new AssemblyCatalog(Assembly.GetExecutingAssembly());
            //var container = new CompositionContainer(catalog);
            //container.ComposeParts(this);

            //AggregateCatalog catalog = new AggregateCatalog();
            //catalog.Catalogs.Add(new DirectoryCatalog(AppDomain.CurrentDomain.SetupInformation.PrivateBinPath));
            //ManagedExtensibilityDependencySolver solver = new ManagedExtensibilityDependencySolver(catalog);
            //DependencyResolver.SetResolver(solver);
        }
    }
}

namespace Newtonsoft.Json.Converters
{
    public class UniversalDateTimeConverter : IsoDateTimeConverter
    {
        public UniversalDateTimeConverter() : base()
        {
            DateTimeFormat = "yyyy-MM-dd HH:mm:ss";
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            return base.ReadJson(reader, objectType, existingValue, serializer);
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            base.WriteJson(writer, value, serializer);
        }
    }
}