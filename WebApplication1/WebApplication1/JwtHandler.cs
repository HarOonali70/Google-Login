using Google.Apis.Auth;
using Identity.Models;
using IdentityCustom.Areas.Identity.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Identity
{
    public class JwtHandler : IJwtHandler
    {
        private readonly IConfiguration _configuration;
        private readonly IConfigurationSection _jwtSettings;
        private readonly IConfigurationSection _goolgeSettings;
        private readonly UserManager<ApplicationUser> _userManager;

        public JwtHandler(IConfiguration configuration, UserManager<ApplicationUser> userManager)
        {
            _configuration = configuration;
            _jwtSettings = _configuration.GetSection("JwtSettings");
            _goolgeSettings = _configuration.GetSection("GoogleAuthSettings");
            _userManager = userManager;
        }

        public async Task<string> GenerateToken(ApplicationUser user)
        {
            try 
            {
                var signingCredentials = GetSigningCredentials();
                var claims = await GetClaims(user);
                var tokenOptions = GenerateTokenOptions(signingCredentials, claims);
                var token = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

                return token;
            }
            catch (Exception ex) {
                throw ex;
            }
            
        }

        public async Task<GoogleJsonWebSignature.Payload> VerifyGoogleToken(ExternalAuthDto externalAuth)
        {
            try
            {
                var settings = new GoogleJsonWebSignature.ValidationSettings()
                {
                    Audience = new List<string>() { _goolgeSettings.GetSection("clientId").Value }
                };

                var payload = await GoogleJsonWebSignature.ValidateAsync(externalAuth.IdToken, settings);

                return payload;
            }
            catch (Exception ex)
            {
                //log an exception
                return null;
            }
        }

        private SigningCredentials GetSigningCredentials()
        {
            var key = Encoding.UTF8.GetBytes(_jwtSettings.GetSection("securityKey").Value);
            var secret = new SymmetricSecurityKey(key);

            return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
        }

        private async Task<List<Claim>> GetClaims(ApplicationUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Email)
            };

            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            return claims;
        }

        private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
        {
            var tokenOptions = new JwtSecurityToken(
                issuer: _jwtSettings["validIssuer"],
                audience: _jwtSettings["validAudience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(10),
                signingCredentials: signingCredentials);

            return tokenOptions;
        }
    }
}
