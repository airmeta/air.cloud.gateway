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
namespace Air.Cloud.GateWay.Options
{
    /// <summary>
    /// 授权服务配置
    /// </summary>
    public class AuthorizationSettings
    {
        /// <summary>
        /// 是否启用授权服务
        /// </summary>
        public bool EnableAuthorizationService { get; set; }
        /// <summary>
        /// 用户访问Token标识
        /// </summary>
        public string AuthorizationHeader { get; set; }
        /// <summary>
        /// 用户刷新Token标识
        /// </summary>
        public string XAuthorizationHeader { get; set; }
        /// <summary>
        /// 授权服务地址
        /// </summary>
        public Authorizationservice AuthorizationService { get; set; }
    }
    public class Authorizationservice
    {
        /// <summary>
        /// IP 地址
        /// </summary>
        public string ServiceIP { get; set; }
        /// <summary>
        /// 端口号
        /// </summary>
        public int ServicePort { get; set; }
    }
}
