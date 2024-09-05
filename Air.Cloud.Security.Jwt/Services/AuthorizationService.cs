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
using Air.Cloud.Core;

using Grpc.Core;

using static Air.Cloud.Core.AuthorizationService;

namespace Air.Cloud.Security.Jwt.Services
{
    public class AuthorizationServices : AuthorizationServiceBase
    {

        public override Task<AuthorizationValidateResult> ValidateAuthorization(AuthorizationValidateContent request, ServerCallContext context)
        {
           var Tuple=JWTEncryption.ValidateToken(request.Authorization,request.XAuthorization);
            AuthorizationValidateResult authorizationValidateResult = new AuthorizationValidateResult()
            {
                IsSuccess = Tuple != null,
                Message = "验证完成",
                UserInformation = Tuple==null?string.Empty:(AppRealization.JSON.Serialize(new
                {
                    User = Tuple.Item1,
                    Authorization = Tuple.Item2,
                    XAuthorization= Tuple.Item3
                }))
            };
            return Task.FromResult(authorizationValidateResult);
        }
    }
}
