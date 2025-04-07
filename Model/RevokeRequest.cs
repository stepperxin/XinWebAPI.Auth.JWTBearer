using System.ComponentModel.DataAnnotations;

namespace XinWebAPI.Auth.JWTBearer.Model
{
    public class RevokeRequest
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}
