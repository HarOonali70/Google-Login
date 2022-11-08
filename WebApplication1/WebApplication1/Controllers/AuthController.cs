using CompanyEmployees.Entities.DataTransferObjects;
using Identity;
using Identity.Models;
using IdentityCustom.Areas.Identity.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IJwtHandler _jwtHandler;
        public AuthController(UserManager<ApplicationUser> userManager,
                              IJwtHandler jwtHandler)
        {
            _userManager = userManager;
            _jwtHandler = jwtHandler;
        }
        [HttpGet, Route("Test")]
        public async Task<ActionResult<string>> Test() 
        {
            return Ok("Get is working");
        }
        [HttpGet, Route("ExternalLogin")]
        public async Task<ActionResult> ExternalLogin([FromBody] ExternalAuthDto externalAuth)
        {
            try
            {
                var payload = await _jwtHandler.VerifyGoogleToken(externalAuth);
                if (payload == null)
                    return BadRequest("Invalid External Authentication.");

                var info = new UserLoginInfo(externalAuth.Provider, payload.Subject, externalAuth.Provider);

                var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
                if (user == null)
                {
                    user = await _userManager.FindByEmailAsync(payload.Email);
                    if (user == null)
                    {
                        user = new ApplicationUser { Email = payload.Email, UserName = payload.Email, FirstName = "test", LastName = "Test" };
                        await _userManager.CreateAsync(user);

                        //prepare and send an email for the email confirmation

                        //await _userManager.AddToRoleAsync(user, "Viewer");
                        await _userManager.AddLoginAsync(user, info);
                    }
                    else
                    {
                        await _userManager.AddLoginAsync(user, info);
                    }
                }

                if (user == null)
                    return BadRequest("Invalid External Authentication.");

                //check for the Locked out account

                var token = await _jwtHandler.GenerateToken(user);

                return Ok(new AuthResponseDto { Token = token, IsAuthSuccessful = true });
            }
            catch (Exception ex) {
                throw ex;
            }
            
        }
    }
}
