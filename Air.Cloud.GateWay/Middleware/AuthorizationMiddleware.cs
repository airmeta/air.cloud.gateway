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
using Air.Cloud.Common.Model;
using Air.Cloud.Core;
using Air.Cloud.Core.App;
using Air.Cloud.Core.Extensions;
using Air.Cloud.Core.Plugins.Security.RSA;
using Air.Cloud.GateWay.Options;

using Grpc.Net.Client;
//using Air.Cloud.Service;
namespace Air.Cloud.GateWay.Middleware
{
    public class AuthorizationMiddleware
    {
        private readonly AuthorizationSettings settings; 
        private readonly RequestDelegate next;
        public AuthorizationMiddleware(RequestDelegate next)
        {
            settings = AppConfigurationLoader.InnerConfiguration.GetConfig<AuthorizationSettings>("AuthorizationSettings");
            this.next = next;
        }
        public async Task InvokeAsync(HttpContext context)
        {
            context.Request.EnableBuffering();
            using (var str=new StreamReader(context.Request.Body))
            {

                var body = await str.ReadToEndAsync();
                context.Request.Body.Position = 0;
                context.Request.Body.Seek(0, SeekOrigin.Begin);
                if (settings.EnableAuthorizationService)
                {
                    bool IsWhiteList = Convert.ToBoolean(context.Request.Headers["WHITE_LIST_REQUEST"]);
                    if (IsWhiteList)
                    {
                        await next(context); // 继续处理请求
                        return;
                    }
                    string? WhiteHeader = context.Request.Headers[settings.WhiteHeader];
                    if (WhiteHeader != null)
                    {
                        context.Request.Headers.Add("USER_INFORMATION", context.Request.Headers["USER_INFORMATION"]);
                        context.Response.Headers.Add("Authorization", context.Request.Headers["Authorization"]);
                        context.Response.Headers.Add("X-Authorization", context.Request.Headers["X-Authorization"]);
                        //验证通过
                        await next(context); // 继续处理请求
                        return;
                    }

                    //启用授权服务验证 开始验证
                    Uri uri = new Uri($"http://{settings.AuthorizationService.ServiceIP}:{settings.AuthorizationService.ServicePort}");
                    var channel = GrpcChannel.ForAddress(uri);
                    try
                    {
                        var client = new AuthorizationService.AuthorizationServiceClient(channel);
                        var Auth = context.Request.Headers["Authorization"];
                        var XAuth = context.Request.Headers["X-Authorization"];
                        if (Auth.IsNullOrEmpty() || XAuth.IsNullOrEmpty())
                        {
                            context.Response.StatusCode = 401;
                            await context.Response.WriteAsync("Authorization Failed");
                        }
                        var call = client.ValidateAuthorization(new AuthorizationValidateContent()
                        {
                            Authorization = Auth,
                            XAuthorization = XAuth,
                            RequestPath = "123"
                        });
                        //请求体
                        if (call.IsSuccess)
                        {
                            var user = AppRealization.JSON.Deserialize<AuthorizationUserInformation>(call.UserInformation);
                            context.Request.Headers.Add("USER_INFORMATION", AppRealization.JSON.Serialize(user.User));
                            context.Response.Headers.Add("Authorization", "Bearer "+user.Authorization);
                            context.Response.Headers.Add("X-Authorization", "Bearer " + user.XAuthorization);
                            //验证通过
                            await next(context); // 继续处理请求
                        }
                        else
                        {
                            //验证失败
                            context.Response.StatusCode = 401;
                            await context.Response.WriteAsync("Authorization Failed");
                        }
                    }
                    catch (Exception ex)
                    {

                        context.Response.StatusCode = 401;
                        await context.Response.WriteAsync("Authorization Failed;"+ex.Message);
                    }

                }
                else
                {
                    await next(context); // 继续处理请求
                }
            }


              
        }
    }
}
