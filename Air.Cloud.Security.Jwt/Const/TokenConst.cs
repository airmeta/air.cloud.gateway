using Air.Cloud.Core.App;

namespace Air.Cloud.Security.Jwt.Const
{
    public class TokenConst
    {
        /// <summary>
        /// 默认AccessToken存储时间
        /// </summary>

        public const int CONST_ACCESS_TOKEN_STORE_HOUR = 1;
        /// <summary>
        /// 默认RefreshToken存储时间
        /// </summary>

        public const int CONST_REFRESH_TOKEN_STORE_HOUR = 1;
        /// <summary>
        /// 默认AccessToken与RefreshToken的延长时间
        /// </summary>

        public const int CONST_EXPIRED_TIME = 10;
        /// <summary>
        ///  默认AccessToken与RefreshToken的延长时间配置Key
        /// </summary>
        public const string EXPIRED_TIME_KEY = "JWTSettings:ExpiredTime";
        /// <summary>
        ///  默认AccessToken与RefreshToken的延长时间配置Key
        /// </summary>
        public const string ACCESS_TOKEN_STORE = "JWTSettings:AccessTokenStore";
        /// <summary>
        ///  默认AccessToken与RefreshToken的延长时间配置Key
        /// </summary>
        public const string REFRESH_TOKEN_STORE = "JWTSettings:RefreshTokenStore";
        /// <summary>
        /// AccessToken存储时间
        /// </summary>
        public static readonly int ACCESS_TOKEN_STORE_HOUR = new Func<int>(() =>
        {
            var Config = AppCore.Configuration[ACCESS_TOKEN_STORE];
            if (Config != null) return Convert.ToInt32(Config);
            return CONST_ACCESS_TOKEN_STORE_HOUR;
        }).Invoke();
        /// <summary>
        /// RefreshToken存储时间
        /// </summary>
        public static readonly int REFRESH_TOKEN_STORE_HOUR = new Func<int>(() =>
        {
            var Config = AppCore.Configuration[REFRESH_TOKEN_STORE];
            if (Config != null) return Convert.ToInt32(Config);
            return CONST_ACCESS_TOKEN_STORE_HOUR;
        }).Invoke();
        /// <summary>
        /// AccessToken与RefreshToken的延长配置时间
        /// </summary>
        public static readonly int EXPIRED_TIME = new Func<int>(() =>
        {
            var Config = AppCore.Configuration[EXPIRED_TIME_KEY];
            if (Config != null) return Convert.ToInt32(Config);
            return CONST_EXPIRED_TIME;
        }).Invoke();
    }
}
