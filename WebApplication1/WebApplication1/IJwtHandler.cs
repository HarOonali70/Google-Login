using Google.Apis.Auth;
using Identity.Models;
using IdentityCustom.Areas.Identity.Data;

namespace Identity
{
    public interface IJwtHandler
    {
        public Task<string> GenerateToken(ApplicationUser user);
        public Task<GoogleJsonWebSignature.Payload> VerifyGoogleToken(ExternalAuthDto externalAuth);
    }
}
