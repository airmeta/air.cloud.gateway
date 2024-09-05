/*
 * Copyright (c) 2024 安徽三实软件科技有限公司
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * This file is provided under the Mozilla Public License Version 2.0,
 * and the "NO WARRANTY" clause of the MPL is hereby expressly
 * acknowledged.
 */
using Air.Cloud.Core.App;
using Air.Cloud.Core.Extensions;
namespace Air.Cloud.GateWay.Middleware
{
    /// <summary>
    /// 白名单中间件
    /// </summary>
    public class WhiteListRequestMiddleware
    {
        private readonly RequestDelegate next;
        private readonly string WhiteListPath = $"{AppConst.ApplicationPath}/whitelist.txt";
        private readonly List<string> WhiteListJSON = new List<string>();
        public WhiteListRequestMiddleware(RequestDelegate next)
        {
            this.next = next;
            var jsonContent = File.ReadAllLines(WhiteListPath);
            WhiteListJSON = jsonContent.IsNullOrEmpty() ? new List<string>() : jsonContent.ToList();
        }
        public async Task InvokeAsync(HttpContext context)
        {
            string Path = context.Request.Path;
            if (WhiteListJSON.Contains(Path)|| Path=="/")
            {
                context.Request.Headers.Add("WHITE_LIST_REQUEST", "true");
                await next(context); // 继续处理请求
                return;
            }
            bool IsWhiteList = false;
            foreach (var item in WhiteListJSON)
            {
                if(Path.StartsWith(item)|| Path.EndsWith(item))
                {
                    IsWhiteList = true;
                    break;
                }
            }
            context.Request.Headers.Add("WHITE_LIST_REQUEST", IsWhiteList.ToString());
            await next(context); // 继续处理请求
        }
    }
}
