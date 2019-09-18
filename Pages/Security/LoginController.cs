using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthSample.Pages.Security
{
    [Route("/Login")]
    [ApiController]
    public class LoginController : Controller
    {
        private readonly IHttpContextAccessor contextAccessor;
        private readonly AuthenticationStateProvider authenticationStateProvider;

        public LoginController(IHttpContextAccessor contextAccessor, AuthenticationStateProvider authenticationStateProvider )
        {
            this.contextAccessor = contextAccessor;
            this.authenticationStateProvider = authenticationStateProvider;
        }

        [HttpPost]
        public async Task Login(LoginViewModel loginViewModel)
        {
            var context = contextAccessor.HttpContext;
            try
            {
                // Clear cookie
                await context
                    .SignOutAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme);
            }
            catch { }

            if (true) //validate user here
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, loginViewModel.UserName),
                };

                var claimsIdentity = new ClaimsIdentity(
                    claims, CookieAuthenticationDefaults.AuthenticationScheme);

                var authProperties = new AuthenticationProperties
                {
                    //AllowRefresh = <bool>,
                    // Refreshing the authentication session should be allowed.

                    //ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                    // The time at which the authentication ticket expires. A
                    // value set here overrides the ExpireTimeSpan option of
                    // CookieAuthenticationOptions set with AddCookie.

                    //IsPersistent = true,
                    // Whether the authentication session is persisted across
                    // multiple requests. When used with cookies, controls
                    // whether the cookie's lifetime is absolute (matching the
                    // lifetime of the authentication ticket) or session-based.

                    //IssuedUtc = <DateTimeOffset>,
                    // The time at which the authentication ticket was issued.

                    //RedirectUri = <string>
                    // The full path or absolute URI to be used as an http
                    // redirect response value.
                };
                var principal = new ClaimsPrincipal(claimsIdentity);
                //this does not work
                (authenticationStateProvider as IHostEnvironmentAuthenticationStateProvider)?
                    .SetAuthenticationState(Task.FromResult(new AuthenticationState(principal)));
                //works somehow, but not for authorizeView
                await context.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    principal,
                    authProperties);
            }
        }
    }
}
