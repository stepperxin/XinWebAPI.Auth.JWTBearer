using System.ComponentModel.DataAnnotations;

namespace XinWebAPI.Auth.JWTBearer.Model
{
    public class RefreshRequest
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}
