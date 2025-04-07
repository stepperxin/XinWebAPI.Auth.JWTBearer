using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using XinWebAPI.Auth.JWTBearer.Model;

namespace XinWebAPI.Auth.JWTBearer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static List<User> Users = new List<User>
        {
            new User
            {
                UserId = "1",
                UserName = "bilbo",
                DisplayName = "BilboBaggins",
                Email = "john@abc.com",
                Password = "1234de@56"
            },
            new User
            {
                UserId = "2",
                UserName = "Frodo",
                DisplayName = "FrodoBaggins",
                Email = "FRodo@abc.com",
                Password = "dedeed@56"
            }
        };

        public IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet("tokenValidate")]
        [Authorize]
        public IActionResult TokenValidate()
        {
            return Ok("Token is valid");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequest loginRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequestErrorMessages();
            }

            var user = await GetUser(loginRequest.Email, loginRequest.Password);

            if(user != null)
            {
                // Add token string to response object and send it back to response
                var authResponse = await GetToken(user);
                return Ok(authResponse);
            }
            else
            {
                return BadRequest("Invalid credentials");
            }
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterRequest registerRequest)
        {
            if (!ModelState.IsValid)
            {
                return BadRequestErrorMessages();
            }

            var isEmailAlreadyRegistered = await GetUserByEmail(registerRequest.Email) != null;

            if (isEmailAlreadyRegistered)
            {
                return Conflict($"Email Id {registerRequest.Email} is already registered");
            }

            await AddUser(new User
            {
                UserName = registerRequest.UserName,
                Email = registerRequest.Email,
                Password = registerRequest.Password,
                DisplayName = registerRequest.UserName
            });

            return Ok("User registered successfully");
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(RefreshRequest request)
        {
            if(!ModelState.IsValid)
            {
                return BadRequestErrorMessages();
            }

            //check if any user with this refresh token exists
            var user = await GetUserByRefreshToken(request.RefreshToken);
            if(user==null)
            {
                return BadRequest("Invalid refresh token");
            }

            //provide new access and refresh token
            var response = await GetToken(user);
            return Ok(response);
        }

        [HttpPost("revoke")]    
        public async Task<IActionResult> Revoke(RevokeRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequestErrorMessages();
            }
            //check if any user with this refresh token exists
            var user = await GetUserByRefreshToken(request.RefreshToken);
            if (user == null)
            {
                return BadRequest("Invalid refresh token");
            }
            //revoke the refresh token
            user.Refreshtoken = null;
            return Ok("Refresh token revoked successfully");
        }

        private async Task<User> AddUser(User newUser)
        {
            newUser.UserId = $"user{DateTime.Now.ToString("hhmmss")}";
            Users.Add(newUser);
            return newUser;
        }
        private async Task<User> GetUser(string email, string password)
        {
            return await Task.FromResult(Users.FirstOrDefault(x => x.Email == email && x.Password == password));

        }
        private async Task<User> GetUserByEmail(string email)
        {
            return await Task.FromResult(Users.FirstOrDefault(x => x.Email == email));
        }
        private async Task<User> GetUserByRefreshToken(string refreshToken)
        {
            return await Task.FromResult(Users.FirstOrDefault(x => x.Refreshtoken == refreshToken));
        }

        private async Task<AuthResponse> GetToken(User user)
        {
            //create claims details based on the user information
            var claims = new[]
            {
                    new Claim(JwtRegisteredClaimNames.Sub, _configuration["token:subject"]),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                    new Claim("UserId", user.UserId),
                    new Claim("UserName", user.UserName),
                    new Claim("DisplayName", user.DisplayName),
                };

            //Create Signing Credentials to sign the JWT token
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["token:key"]));
            var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            //Create the JWT token
            var token = new JwtSecurityToken(
                _configuration["token:issuer"],
                _configuration["token:audience"],
                claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["token:accessTokenExpiryMinutes"])),
                signingCredentials: signIn
            );

            // Serialize the token to a string
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            var refreshToken = GetRefreshToken();
            user.Refreshtoken = refreshToken;

            // Add token string to response object and send it back to response
            var authResponse = new AuthResponse
            {
                AccessToken = tokenString,
                RefreshToken = refreshToken
            };

            return await Task.FromResult(authResponse);
        }

        // the refresh token is a base64 encoded string, is not a JWT token and it is stored with the user info
        private string GetRefreshToken()
        { 
            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
            // ensure token is unique
            var tokenisUnique = !Users.Any(x => x.Refreshtoken == token);
            if (!tokenisUnique)
            {
                return GetRefreshToken();
            }
            return token;
        }

        private IActionResult BadRequestErrorMessages()
        {
            var errMsg = ModelState.Values.SelectMany(x => x.Errors).Select(x => x.ErrorMessage).ToList();
            return BadRequest(errMsg);
        }
    }
}
