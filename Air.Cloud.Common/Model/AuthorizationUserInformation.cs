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
namespace Air.Cloud.GateWay.Model
{
    /// <summary>
    /// 用户信息结果
    /// </summary>
    public class AuthorizationUserInformation
    {
        /// <summary>
        /// 用户信息
        /// </summary>
        public Dictionary<string,string> User { get; set; }
        /// <summary>
        /// 用户Token
        /// </summary>
        public string Authorization { get; set; }
        /// <summary>
        /// 用户刷新Token
        /// </summary>
        public string XAuthorization { get; set; }
    }
}
