using System.ComponentModel.DataAnnotations;

namespace XinWebAPI.Auth.JWTBearer.Model
{
    public class LoginRequest
    {
        [Required]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
