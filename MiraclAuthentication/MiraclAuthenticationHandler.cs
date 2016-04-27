using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Miracl
{
    internal class MiraclAuthenticationHandler : AuthenticationHandler<MiraclAuthenticationOptions>
    {
        private readonly MiraclClient miraclClient;
        private readonly ILogger logger;

        public MiraclAuthenticationHandler(MiraclClient client, ILogger logger)
        {
            this.miraclClient = client;
            this.logger = logger;
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (challenge != null)
            {
                var state = challenge.Properties;
                if (string.IsNullOrEmpty(state.RedirectUri))
                {
                    state.RedirectUri = Request.Uri.ToString();
                }

                // Anti-CSRF
                GenerateCorrelationId(state);
                var stateString = Options.StateDataFormat.Protect(state);
                string baseUri = Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase;
                string redirectUri = this.miraclClient.GetAuthorizationRequestUrl(baseUri, Options, stateString);
                Response.Redirect(redirectUri);
            }

            return Task.FromResult<object>(null);
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;
            try
            {
                properties = Options.StateDataFormat.Unprotect(Request.Query["state"]);
                if (properties == null)
                {
                    logger.WriteWarning("Rejected authentication response - invalid state!");
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, this.logger))
                {
                    logger.WriteWarning("Rejected authentication response - invalid anti-forgery token!");
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;
                var response = await this.miraclClient.ValidateAuthorization(Request.Query, Options, redirectUri);
                if (response == null)
                {                    
                    logger.WriteWarning("Access token was not found!");
                    return new AuthenticationTicket(null, properties);
                }

                var identity = await this.miraclClient.GetIdentity(response);
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, this.miraclClient.UserId, ClaimValueTypes.String, Options.AuthenticationType));
                identity.AddClaim(new Claim(ClaimTypes.Email, this.miraclClient.Email, ClaimValueTypes.String, Options.AuthenticationType));                
                return new AuthenticationTicket(identity, properties);
            }
            catch (Exception ex)
            {
                logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                if (Options.SignInAsAuthenticationType != null && ticket.Identity != null)
                {
                    ClaimsIdentity grantIdentity = ticket.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, Options.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, Options.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }

                    Context.Authentication.SignIn(ticket.Properties, grantIdentity);
                }

                if (!string.IsNullOrEmpty(ticket.Properties.RedirectUri))
                {
                    Response.Redirect(ticket.Properties.RedirectUri);
                    return true;
                }
            }
            return false;
        }
    }
}