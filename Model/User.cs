using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XinWebAPI.Auth.JWTBearer.Model
{
    public class User : IdentityUser
    {
        public string? DisplayName { get; set; }
        public DateTime? DateOfBirth { get; set; }
        public string? Address { get; set; }
        public string? City { get; set; }
        public string? State { get; set; }
        public string? Country { get; set; }
        public string? RefreshToken { get; set; } // refresh token for this user
    }
}
