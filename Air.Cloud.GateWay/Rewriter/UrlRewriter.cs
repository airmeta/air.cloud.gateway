using Air.Cloud.Common.Model;
using Air.Cloud.Core.App;
using Air.Cloud.WebApp.Extensions;

namespace Air.Cloud.GateWay.Rewriter
{
    public class UrlRewriter : IUrlRewriter
    {
        /// <summary>
        /// 代理配置信息
        /// </summary>
        private ProxySetting Settings => AppConfigurationLoader.InnerConfiguration.GetConfig<ProxySetting>("ProxySettings");

        /// <summary>
        /// 是否存在需要代理的地址
        /// </summary>
        /// <param name="Path"></param>
        /// <returns></returns>
        private ProxyRoute? GetProxyRoute(string Path)
        {
            if (Settings == null) { return null; }
            return Settings.Routes.Where(s => s.ProxyPath.StartsWith(Path)).FirstOrDefault();
        }

        public Task<Uri> RewriteUri(HttpContext context)
        {
            var request = context.Request;
            string path = request.Path;
            ProxyRoute? proxyRoute = GetProxyRoute(path);
            //拦截请求地址信息 并将其重定向到其他地址
            if (proxyRoute!=null)
            {
                Uri TargetUri = new Uri(new Uri(proxyRoute.GateWayAddress??Settings.GateWayAddress), proxyRoute.TargetPath);
                return Task.FromResult(TargetUri);
            }
            return Task.FromResult(new Uri(request.GetRequestUrlAddress()));
        }
    }
}
