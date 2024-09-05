/*
 * Copyright (c) 2024 ������ʵ����Ƽ����޹�˾
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
using Air.Cloud.HostApp.Extensions;
using Air.Cloud.Security.Jwt;

using Microsoft.AspNetCore.Server.Kestrel.Core;

using System.Net;
var builder = Host.CreateDefaultBuilder(args)
                .UseWindowsService()
                .HostInjectInFile();
int Settings =Convert.ToInt32(AppCore.Configuration["AuthorizationSettings:ServicePort"]??"6735");
builder.ConfigureWebHostDefaults(webBuilder =>
{
                    //��ʽ���� TLS����������������ã����򷢲���ֻ�ܼ���localhost��һ��ip����ʹ���޸���launchSettings.json��applicationUrlҲ�޷���Ч
                    webBuilder.ConfigureKestrel(options =>
                    {
                        options.Listen(IPAddress.Any, Settings, listenOptions =>
                        {
                            listenOptions.Protocols = HttpProtocols.Http2;
                        });
                    });
                    webBuilder.UseStartup<Startup>();
                });
var app = builder.Build();
app.Run();
