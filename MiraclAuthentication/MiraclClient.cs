using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using SystemClaims = System.Security.Claims;

namespace Miracl
{
    /// <summary>
    /// Relying Party client class for connecting to the MIRACL server.
    /// </summary>
    public class MiraclClient
    {
        #region Fields
        internal OpenIdConnectConfiguration config;
        internal UserInfoResponse userInfo;
        internal string callbackUrl;
        private TokenResponse accessTokenResponse;
        private List<SystemClaims.Claim> claims;
        #endregion

        #region C'tor
        /// <summary>
        /// Initializes a new instance of the <see cref="MiraclClient"/> class.
        /// </summary>
        public MiraclClient()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MiraclClient"/> class.
        /// </summary>
        /// <param name="options">The options which describes the authenticating parameters.</param>
        public MiraclClient(MiraclAuthenticationOptions options)
            : this()
        {
            this.Options = options;
        }

        #endregion

        #region Members
        /// <summary>
        /// Specifies the MIRACL client objects for authentication.
        /// </summary>
        /// <value>
        /// The options values.
        /// </value>
        public MiraclAuthenticationOptions Options
        {
            get;
            private set;
        }

        /// <summary>
        /// Opaque value set by the RP to maintain state between request and callback.
        /// </summary>
        /// </value>
        /// The State value.
        /// </value>
        public string State
        {
            get;
            internal set;
        }

        /// <summary>
        /// String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
        /// </summary>
        /// <value>
        /// The Nonce value.
        /// </value>
        public string Nonce
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the user identifier name when authenticated.
        /// </summary>
        /// <value>
        /// The user identifier name.
        /// </value>
        public string UserId
        {
            get
            {
                return TryGetValue("sub");
            }
        }

        /// <summary>
        /// Gets the email of the authentication.
        /// </summary>
        /// <value>
        /// The email.
        /// </value>
        public string Email
        {
            get
            {
                return TryGetValue("email");
            }
        }

        #endregion

        #region Methods
        #region Public
        /// <summary>
        /// Constructs redirect URL for authorization via M-Pin system. After URL
        /// redirects back, pass the query string to ValidateAuthorization method to complete
        /// the authorization with server.
        /// </summary>
        /// <param name="baseUri">The base URI of the calling app.</param>
        /// <param name="options">The options for authentication.</param>
        /// <param name="stateString">(Optional) Specify a new Open ID Connect state.</param>
        /// <exception cref="ArgumentException">
        /// <paramref name="baseUri"/> is not a valid Uri.
        /// </exception>
        /// <returns>The callback url.</returns>
        public async Task<string> GetAuthorizationRequestUrlAsync(string baseUri, MiraclAuthenticationOptions options = null, string stateString = null)
        {
            if (!Uri.IsWellFormedUriString(baseUri, UriKind.RelativeOrAbsolute))
            {
                throw new ArgumentException("The baseUri is not well formed", "baseUri");
            }

            await LoadOpenIdConnectConfigurationAsync();
            return GetAuthorizationRequestUrl(baseUri, options, stateString);
        }

        /// <summary>
        /// Returns response with the access token if validation succeeds or None if query string
        /// doesn't contain code and state.
        /// </summary>
        /// <param name="requestQuery">The query string returned from authorization URL.</param>
        /// <param name="redirectUri">The redirect URI. If not specified, it will be taken from the authorization request.</param>
        /// <returns>
        /// The access token from the authentication response.
        /// </returns>
        public async Task<TokenResponse> ValidateAuthorization(NameValueCollection requestQuery, string redirectUri = "")
        {
            if (requestQuery == null)
            {
                throw new ArgumentNullException("requestQuery");
            }

            if (Options == null)
            {
                throw new InvalidOperationException("No Options for authentication! ValidateAuthorization method should be called first!");
            }

            string code = requestQuery[Constants.Code];
            string returnedState = requestQuery[Constants.State];

            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(returnedState))
            {
                throw new ArgumentException(
                    string.Format("requestQuery does not have the proper \"{0}\" and \"{1}\" parameteres.", Constants.Code, Constants.State), "requestQuery");
            }

            if (!State.Equals(returnedState, StringComparison.Ordinal))
            {
                throw new ArgumentException("Invalid state!");
            }

            if (string.IsNullOrEmpty(redirectUri) && string.IsNullOrEmpty(callbackUrl))
            {
                throw new ArgumentException("Empty redirect uri!");
            }

            if (string.IsNullOrEmpty(redirectUri))
            {
                redirectUri = callbackUrl;
            }

            var client = this.Options.BackchannelHttpHandler != null
                          ? new TokenClient(config.TokenEndpoint, this.Options.ClientId, this.Options.ClientSecret, this.Options.BackchannelHttpHandler)
                          : new TokenClient(config.TokenEndpoint, this.Options.ClientId, this.Options.ClientSecret);

            client.Timeout = this.Options.BackchannelTimeout;
            client.AuthenticationStyle = AuthenticationStyle.PostValues;

            this.accessTokenResponse = await client.RequestAuthorizationCodeAsync(code, redirectUri);
            return this.accessTokenResponse;
        }

        /// <summary>
        /// Clears the user authorization information.
        /// </summary>
        /// <param name="includingAuth">if set to <c>true</c> the user authentication data is also cleaned.</param>
        public void ClearUserInfo(bool includingAuth = true)
        {
            if (includingAuth)
            {
                this.State = null;
                this.Nonce = null;
                this.Options = null;
            }

            this.callbackUrl = null;
            this.userInfo = null;
            this.accessTokenResponse = null;
        }

        /// <summary>
        /// Determines whether this instance is authorized.
        /// </summary>
        /// <returns>Returns True if access token for the user is available. </returns>
        public bool IsAuthorized()
        {
            return this.accessTokenResponse != null;
        }

        /// <summary>
        /// Gets the identity given by the authentication.
        /// </summary>
        /// <param name="response">The response from the authentication.</param>
        /// <returns></returns>
        /// <exception cref="System.Exception">ValidateAuthorization method should be called first!</exception>
        public async Task<ClaimsIdentity> GetIdentity(TokenResponse response)
        {
            if (response == null)
            {
                throw new ArgumentNullException("response");
            }

            if (Options == null)
            {
                throw new InvalidOperationException("No Options for authentication! ValidateAuthorization method should be called first!");
            }

            await FillClaimsAsync(response);
            return new ClaimsIdentity(this.claims,
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
        }

        #endregion

        #region Private
        /// <summary>
        /// Constructs redirect URL for authorization via M-Pin system to be redirected to.
        /// </summary>
        /// <param name="baseUri">The base URI.</param>
        /// <param name="options">The options.</param>
        /// <param name="stateString">The state string.</param>
        /// <returns>Uri for authorization to be redirected to.</returns>
        /// <exception cref="System.ArgumentException">MiraclAuthenticationOptions should be set!</exception>
        private string GetAuthorizationRequestUrl(string baseUri, MiraclAuthenticationOptions options = null, string stateString = null)
        {
            this.Options = options ?? this.Options;
            if (this.Options == null)
            {
                throw new ArgumentNullException("MiraclAuthenticationOptions should be set!");
            }
            
            this.State = stateString ?? Guid.NewGuid().ToString("N");
           
            byte[] nonceBytes = new byte[16]; 
            using (RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create())
            {
                randomNumberGenerator.GetBytes(nonceBytes);
            }

            this.Nonce = string.Concat(nonceBytes.Select(b => b.ToString("x2")));

            this.callbackUrl = baseUri.TrimEnd('/') + this.Options.CallbackPath;

            var authRequest = new AuthorizeRequest(config.AuthorizationEndpoint);
            return authRequest.CreateAuthorizeUrl(clientId: this.Options.ClientId,
                                                    responseType: Constants.Code,
                                                    scope: Constants.Scope,
                                                    redirectUri: callbackUrl,
                                                    state: this.State,
                                                    nonce: this.Nonce);
        }

        private async Task LoadOpenIdConnectConfigurationAsync()
        {
            if (config == null)
            {
                string discoveryAddress = string.IsNullOrEmpty(this.Options.PlatformAPIAddress) ? Constants.ServerBaseAddress : this.Options.PlatformAPIAddress;
                var manager = new ConfigurationManager<OpenIdConnectConfiguration>(discoveryAddress + Constants.DiscoveryPath);
                config = await manager.GetConfigurationAsync();
            }
        }

        internal async Task FillClaimsAsync(TokenResponse response)
        {
            if (response == null || string.IsNullOrWhiteSpace(response.IdentityToken) || string.IsNullOrEmpty(response.AccessToken))
            {
                throw new ArgumentNullException("The response, its IdentityToken or AccessToken are null!");
            }

            this.claims = new List<SystemClaims.Claim>();
            this.claims.Clear();

            this.claims.AddRange(await GetUserInfoClaimsAsync(response.AccessToken));
            this.claims.Add(new Claim(Constants.AccessToken, response.AccessToken));
            this.claims.Add(new Claim(Constants.ExpiresAt, (DateTime.UtcNow.ToEpochTime() + response.ExpiresIn).ToDateTimeFromEpoch().ToString()));

            if (!string.IsNullOrWhiteSpace(response.RefreshToken))
            {
                this.claims.Add(new Claim(Constants.RefreshToken, response.RefreshToken));
            }
        }

        private async Task<IEnumerable<Claim>> GetUserInfoClaimsAsync(string accessToken)
        {
            UserInfoClient client = this.Options.BackchannelHttpHandler != null
                ? new UserInfoClient(new Uri(config.UserInfoEndpoint), accessToken, this.Options.BackchannelHttpHandler)
                : new UserInfoClient(new Uri(config.UserInfoEndpoint), accessToken);

            this.userInfo = await client.GetAsync();

            var claims = new List<Claim>();
            if (this.userInfo.Claims != null)
            {
                this.userInfo.Claims.ToList().ForEach(ui => claims.Add(new Claim(ui.Item1, ui.Item2)));
            }

            return claims;
        }

        internal string TryGetValue(string propertyName)
        {
            if (this.userInfo == null || this.userInfo.JsonObject == null)
                return string.Empty;

            JToken value;
            return this.userInfo.JsonObject.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
        #endregion
        #endregion
    }
}
