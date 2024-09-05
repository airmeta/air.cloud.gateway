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
using Air.Cloud.Plugins.Jwt.Options;

namespace Air.Cloud.Security.Jwt
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddOptions<JWTSettingsOptions>()
              .BindConfiguration("JWTSettings")
              .ValidateDataAnnotations()
              .PostConfigure(options =>
              {
                  _ = JWTEncryption.SetDefaultJwtSettings(options);
              });
            // 配置Grpc
            services.AddGrpc(options =>
            {
                options.EnableDetailedErrors = true;
                options.MaxReceiveMessageSize = null; //null代表不受限制 (如果填写2 * 1024 * 1024，则代表最大接收是2 MB)
                options.MaxSendMessageSize = null; //null代表不受限制 (如果填写5 * 1024 * 1024，则代表最大发送是5 MB)     =
            });
        }
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGrpcService<Services.AuthorizationServices>();
            });
        }
    }
}