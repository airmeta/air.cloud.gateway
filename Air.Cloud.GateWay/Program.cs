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
using Air.Cloud.GateWay.Middleware;
using Air.Cloud.Modules.Consul.Model;
using Air.Cloud.Modules.Consul.Util;
using Air.Cloud.WebApp.App;

using Microsoft.AspNetCore.Server.Kestrel.Core;

using Ocelot.Cache.CacheManager;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using Ocelot.Provider.Consul;
using Ocelot.Provider.Polly;

using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
var builder = WebApplication.CreateBuilder(args);
#region 注入配置文件

#region 加载配置信息
var options = AppConfigurationLoader.InnerConfiguration.GetConfig<ConsulServiceOptions>();
var Config = ConfigurationLoader.LoadRemoteConfiguration(options);
ConfigurationManager configurationManager = new ConfigurationManager();
configurationManager.AddConfiguration(Config.Item1);
configurationManager.AddConfiguration(Config.Item2);
#endregion

//注入网关配置文件
builder.Services.AddOcelot(configurationManager).AddCacheManager(x =>
{
    x.WithDictionaryHandle();
}).AddConsul().AddPolly();

string AllowCors = AppConfigurationLoader.InnerConfiguration["AllowCors"];
builder.Services.AddCors(options => options.AddPolicy("CorsPolicy",
    builde =>
    {
        builde.AllowAnyMethod()
        .WithOrigins(AllowCors.Split(","))
        .AllowAnyHeader()
        .AllowCredentials();
}));
#endregion

var app = builder.WebInjectInFile();
app.UseCors("CorsPolicy");
app.UseMiddleware<WhiteListRequestMiddleware>();
app.UseMiddleware<IPMiddleware>();
app.UseMiddleware<AuthorizationMiddleware>();
app.UseOcelot().Wait();
app.Run();
