using Air.Cloud.Common.Model;
using Air.Cloud.Core.App;

using Ocelot.Values;
using Air.Cloud.GateWay.Client;
using Air.Cloud.GateWay.Rewriter;
namespace Air.Cloud.GateWay.Middleware
{
    public class UrlProxyMiddleware
    {
        private readonly ProxySetting settings;
        private readonly RequestDelegate next;
        public UrlProxyMiddleware(RequestDelegate next)
        {
            settings = AppConfigurationLoader.InnerConfiguration.GetConfig<ProxySetting>("ProxySettings");
            this.next = next;
        }
        public async Task InvokeAsync(HttpContext context)
        {
            if (!IsInitProxy)
            {
                services.AddHttpClient<ProxyHttpClient>()
                .ConfigurePrimaryHttpMessageHandler(x => new HttpClientHandler()
                {
                    AllowAutoRedirect = false,
                    MaxConnectionsPerServer = int.MaxValue,
                    UseCookies = false,
                });
                IsInitProxy = true;
            }
            services.AddSingleton<IUrlRewriter>(new T());
            return services;
        }
    }
}
