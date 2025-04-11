using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XinWebAPI.Auth.JWTBearer.Utilities
{
    internal static class Constants
    {
        internal const string TokenIssuer = "XinWebAPI.Auth.JWTBearer:token:issuer";
        internal const string TokenAudience = "XinWebAPI.Auth.JWTBearer:token:audience";
        internal const string TokenKey = "XinWebAPI.Auth.JWTBearer:token:key";
        internal const string TokenSubject = "XinWebAPI.Auth.JWTBearer:token:subject";
        internal const string TokenMinuteExpiration = "XinWebAPI.Auth.JWTBearer:token:accessTokenExpiryMinutes";
        internal const string DBConnectionString = "XinWebAPI.Auth.JWTBearer";
    }
}
