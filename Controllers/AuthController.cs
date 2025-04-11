using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using XinWebAPI.Auth.JWTBearer.Model;
using XinWebAPI.Auth.JWTBearer.Utilities;

namespace XinWebAPI.Auth.JWTBearer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        public IConfiguration _configuration;
        public UserManager<User> _userManager;

        public AuthController(IConfiguration configuration, UserManager<User> userManager)
        {
            _configuration = configuration;
            _userManager = userManager;
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

            var user = await _userManager.FindByEmailAsync(loginRequest.Email);
            var isAuthorized = user != null && await _userManager.CheckPasswordAsync(user,loginRequest.Password);

            if (isAuthorized)
            {
                // Add token string to response object and send it back to response
                var authResponse = await GetToken(user);
                user.RefreshToken = authResponse.RefreshToken;
                await _userManager.UpdateAsync(user);
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

            var isEmailAlreadyRegistered = await _userManager.FindByEmailAsync(registerRequest.Email) != null;
            var isUserNameAlreadyRegisteres = await _userManager.FindByNameAsync(registerRequest.UserName) != null;

            if (isEmailAlreadyRegistered)
            {
                return Conflict($"Email Id {registerRequest.Email} is already registered");
            }
            if (isUserNameAlreadyRegisteres)
            {
                return Conflict($"Username Id {registerRequest.UserName} is already registered");
            }

            var newUser = new User
            {
                UserName = registerRequest.UserName,
                Email = registerRequest.Email,
                //Password = registerRequest.Password,
                //DisplayName = registerRequest.UserName
            };

            var result = await _userManager.CreateAsync(newUser, registerRequest.Password);

            if (result.Succeeded)
            {
                return Ok("User registered successfully");
            }
            else
            {
                return StatusCode(500, result.Errors.Select(e => new { Msg = e.Code, Desc = e.Description }).ToList());
            }
            
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(RefreshRequest request)
        {
            if(!ModelState.IsValid)
            {
                return BadRequestErrorMessages();
            }

            //check if any user with this refresh token exists
            var user = _userManager.Users.FirstOrDefault(u => u.RefreshToken == request.RefreshToken);
            if(user==null)
            {
                return BadRequest("Invalid refresh token");
            }

            //provide new access and refresh token
            var response = await GetToken(user);
            user.RefreshToken = response.RefreshToken;
            await _userManager.UpdateAsync(user);
            return Ok(response);
        }

        [HttpPost("revoke")]
        [Authorize]
        public async Task<IActionResult> Revoke(RevokeRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequestErrorMessages();
            }

            // fetch email from the claims of currently logged in user
            var userEmail = this.HttpContext.User.FindFirstValue("Email");

            // check if the user is logged in
            var user = !string.IsNullOrEmpty(userEmail) ? await _userManager.FindByEmailAsync(userEmail) : null;
            if (user == null || user.RefreshToken != request.RefreshToken)
            {
                return BadRequest("Invalid refresh token");
            }
            //revoke the refresh token
            user.RefreshToken = null;
            await _userManager.UpdateAsync(user);
            return Ok("Refresh token revoked successfully");
        }

        private async Task<AuthResponse> GetToken(User user)
        {
            //create claims details based on the user information
            var claims = new[]
            {
                    new Claim(JwtRegisteredClaimNames.Sub, _configuration[Constants.TokenSubject]),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                    new Claim("UserId", user.Id),
                    new Claim("UserName", user.UserName),
                    //new Claim("DisplayName", user.DisplayName),
                };

            //Create Signing Credentials to sign the JWT token
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration[Constants.TokenKey]));
            var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            //Create the JWT token
            var token = new JwtSecurityToken(
                _configuration[Constants.TokenIssuer],
                _configuration[Constants.TokenAudience],
                claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration[Constants.TokenMinuteExpiration])),
                signingCredentials: signIn
            );

            // Serialize the token to a string
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            var refreshToken = GetRefreshToken();
            user.RefreshToken = refreshToken;

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
            var tokenisUnique = !_userManager.Users.Any(x => x.RefreshToken == token);
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
