using Microsoft.AspNetCore.Http;

namespace Air.Cloud.GateWay.Rewriter
{
    public interface IUrlRewriter
    {
        /// <summary>
        /// 重写Url
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        Task<Uri> RewriteUri(HttpContext context);
    }
}
