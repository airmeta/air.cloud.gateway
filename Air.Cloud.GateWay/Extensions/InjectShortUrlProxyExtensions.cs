using Air.Cloud.GateWay.Client;
using Air.Cloud.GateWay.Rewriter;

namespace Air.Cloud.GateWay.Extensions
{
    public static class InjectShortUrlProxyExtensions
    {

        public static bool IsInitProxy = false;

        /// <summary>
        /// Web服务注入代理
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="services"></param>
        /// <returns></returns>
        public static IServiceCollection WebInjectProxy<T>(this IServiceCollection services) where T : IUrlRewriter, new()
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
