/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Casperinc.IdentityProvider.Data.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Core;
using OpenIddict.Models;

namespace AuthorizationServer.Controllers
{

	[Route("identityprovider/")]
	public class AuthorizationController : Controller
	{
		private readonly OpenIddictApplicationManager<OpenIddictApplication> _applicationManager;
        private SignInManager<User> _signInManager;
        private UserManager<User> _userManager;
        private IOptions<IdentityOptions> _identityOptions;

        public AuthorizationController(
			OpenIddictApplicationManager<OpenIddictApplication> applicationManager,
			SignInManager<User> signInManager,
			UserManager<User> userManager,
            IOptions<IdentityOptions> identityOptions)
		{
			_applicationManager = applicationManager;
            _signInManager = signInManager;
            _userManager = userManager;
            _identityOptions = identityOptions;
		}

		[HttpPost("connect/token"), Produces("application/json")]
		public async Task<IActionResult> Exchange(OpenIdConnectRequest request)
		{
			Debug.Assert(request.IsTokenRequest(),
				"The OpenIddict binder for ASP.NET Core MVC is not registered. " +
				"Make sure services.AddOpenIddict().AddMvcBinders() is correctly called.");

			 if(request.IsPasswordGrantType())
            {

				var user = await _userManager.FindByNameAsync(request.Username);
				if (user == null)
				{
					return BadRequest(new OpenIdConnectResponse
					{
						Error = OpenIdConnectConstants.Errors.InvalidGrant,
						ErrorDescription = "The username/password couple is invalid."
					});
				}


                // Ensure the user is allowed to sign in.
                if (!await _signInManager.CanSignInAsync(user))
                {
                    return BadRequest(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = "The specified user is not allowed to sign in."
                    });
                }

                // Ensure the user is not already locked out.
                if (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user))
                {
                    return BadRequest(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = "The username/password couple is invalid."
                    });
                }

                // Ensure the password is valid.
                if (!await _userManager.CheckPasswordAsync(user, request.Password))
                {
                    if (_userManager.SupportsUserLockout)
                    {
                        await _userManager.AccessFailedAsync(user);
                    }

                    return BadRequest(new OpenIdConnectResponse
                    {
                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = "The username/password couple is invalid."
                    });
                }

                if (_userManager.SupportsUserLockout)
                {
                    await _userManager.ResetAccessFailedCountAsync(user);
                }

				// Create a new authentication ticket.
				var ticket = await CreateTicketAsyncForUser(request, user);

				return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
			}

			return BadRequest(new OpenIdConnectResponse
			{
				Error = OpenIdConnectConstants.Errors.UnsupportedGrantType,
				ErrorDescription = "The specified grant type is not supported."
			});
		}



        [HttpGet("connect/logout")]
        public async Task<IActionResult> Logout()
        {
            // Ask ASP.NET Core Identity to delete the local and external cookies created
            // when the user agent is redirected from the external identity provider
            // after a successful authentication flow (e.g Google or Facebook).
            await _signInManager.SignOutAsync();

            // Returning a SignOutResult will ask OpenIddict to redirect the user agent
            // to the post_logout_redirect_uri specified by the client application.
            return SignOut(OpenIdConnectServerDefaults.AuthenticationScheme);
        }


        private async Task<AuthenticationTicket> CreateTicketAsyncForUser(OpenIdConnectRequest request, User user)
		{
			// Create a new ClaimsPrincipal containing the claims that
			// will be used to create an id_token, a token or a code.
			var principal = await _signInManager.CreateUserPrincipalAsync(user);

			// Create a new authentication ticket holding the user identity.
			var ticket = new AuthenticationTicket(principal,
				new Microsoft.AspNetCore.Authentication.AuthenticationProperties(),
				OpenIdConnectServerDefaults.AuthenticationScheme);

			// Set the list of scopes granted to the client application.

			ticket.SetScopes(new[]
			{
				OpenIdConnectConstants.Scopes.OpenId,
				OpenIdConnectConstants.Scopes.Email,
				OpenIdConnectConstants.Scopes.Profile,
				OpenIddictConstants.Scopes.Roles
			}.Intersect(request.GetScopes()));

			ticket.SetResources("Casperinc.MainSite.API");

			// Note: by default, claims are NOT automatically included in the access and identity tokens.
			// To allow OpenIddict to serialize them, you must attach them a destination, that specifies
			// whether they should be included in access tokens, in identity tokens or in both.

			foreach (var claim in ticket.Principal.Claims)
			{
				// Never include the security stamp in the access and identity tokens, as it's a secret value.
				if (claim.Type == _identityOptions.Value.ClaimsIdentity.SecurityStampClaimType)
				{
					continue;
				}

				var destinations = new List<string>
				{
					OpenIdConnectConstants.Destinations.AccessToken
				};

				// Only add the iterated claim to the id_token if the corresponding scope was granted to the client application.
				// The other claims will only be added to the access_token, which is encrypted when using the default format.
				if ((claim.Type == OpenIdConnectConstants.Claims.Name && ticket.HasScope(OpenIdConnectConstants.Scopes.Profile)) ||
					(claim.Type == OpenIdConnectConstants.Claims.Email && ticket.HasScope(OpenIdConnectConstants.Scopes.Email)) ||
					(claim.Type == OpenIdConnectConstants.Claims.Role && ticket.HasScope(OpenIddictConstants.Claims.Roles)))
				{
					destinations.Add(OpenIdConnectConstants.Destinations.IdentityToken);
				}

				claim.SetDestinations(destinations);
			}

			return ticket;
		}


	}
}