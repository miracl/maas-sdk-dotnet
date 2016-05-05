using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Newtonsoft.Json.Linq;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Security.Claims;
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
        public MiraclAuthenticationOptions Options;
        public string State, Nonce;

        internal UserInfoResponse UserInfo;
        
        private string redirectUrl;
        private TokenResponse accessTokenResponse;
        private ClaimsIdentity identity;
        private List<SystemClaims.Claim> claims;
        private OpenIdConnectConfiguration config;
        #endregion

        #region C'tor
        /// <summary>
        /// Initializes a new instance of the <see cref="MiraclClient"/> class.
        /// </summary>
        public MiraclClient()
        {
            ClearUserInfo();            
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MiraclClient"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        public MiraclClient(MiraclAuthenticationOptions options) : this() 
        {
            this.Options = options;
        }

        #endregion

        #region Members

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
        /// <returns>The callback url.</returns>
        public async Task<string> GetAuthorizationRequestUrlAsync(string baseUri, MiraclAuthenticationOptions options = null, string stateString = null)
        {
            await LoadOpenIdConnectConfigurationAsync();
            return GetAuthorizationRequestUrl(baseUri, options, stateString);
        }
        
        /// <summary>
        /// Returns response with the access token if validation succeeds or None if query string
        /// doesn't contain code and state.
        /// </summary>
        /// <param name="requestQuery">The query string returned from authorization URL.</param>
        /// <param name="options">The options for authentication.</param>
        /// <param name="redirectUri">The redirect URI. If not specified, it will be taken from the authorization request.</param>
        /// <returns>The access token from the authentication response.</returns>
        public async Task<TokenResponse> ValidateAuthorization(IEnumerable requestQuery, MiraclAuthenticationOptions options = null, string redirectUri = "")
        {
            string code = null;
            string returnedState = null;
            this.Options = options ?? this.Options;

            GetValuesBasedOnType(requestQuery, ref code, ref returnedState);

            if (false == State.Equals(returnedState, StringComparison.Ordinal) ||
                (string.IsNullOrEmpty(redirectUri) && string.IsNullOrEmpty(redirectUrl)))
            {
                return null;
            }

            if (string.IsNullOrEmpty(redirectUri))
            {
                redirectUri = redirectUrl;
            }

            var client = new TokenClient(config.TokenEndpoint, this.Options.ClientId, this.Options.ClientSecret);
            client.Timeout = this.Options.BackchannelTimeout;
            client.AuthenticationStyle = AuthenticationStyle.BasicAuthentication;

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

            this.redirectUrl = null;
            this.UserInfo = null;
            this.identity = null;
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
            if (Options == null)
                throw new Exception("No Options for authentication! ValidateAuthorization method should be called first!");

            await FillClaimsAsync(response);
            this.identity = new ClaimsIdentity(this.claims,
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

            return this.identity;
        }

        #endregion

        #region Internal
        /// <summary>
        /// Constructs redirect URL for authorization via M-Pin system to be redirected to.
        /// </summary>
        /// <param name="baseUri">The base URI.</param>
        /// <param name="options">The options.</param>
        /// <param name="stateString">The state string.</param>
        /// <returns>Uri for authorization to be redirected to.</returns>
        /// <exception cref="System.ArgumentException">MiraclAuthenticationOptions should be set!</exception>
        internal string GetAuthorizationRequestUrl(string baseUri, MiraclAuthenticationOptions options = null, string stateString = null)
        {
            this.Options = options ?? this.Options;
            if (this.Options == null)
                throw new ArgumentException("MiraclAuthenticationOptions should be set!");

            this.State = stateString ?? Guid.NewGuid().ToString("N");
            this.Nonce = Guid.NewGuid().ToString("N");
            this.redirectUrl = baseUri + this.Options.CallbackPath;

            // space separated
            string scope = string.Join(" ", this.Options.Scope);
            if (string.IsNullOrEmpty(scope))
            {
                scope = "openid profile email";
            }

            var authRequest = new AuthorizeRequest(config.AuthorizationEndpoint);
            return authRequest.CreateAuthorizeUrl(clientId: this.Options.ClientId,
                                                    responseType: "code",
                                                    scope: scope,
                                                    redirectUri: redirectUrl,
                                                    state: this.State,
                                                    nonce: this.Nonce);
        }

        #endregion 

        #region Private

        private async Task LoadOpenIdConnectConfigurationAsync()
        {
            var discoAddress = Constants.DiscoveryEndpoint + "/.well-known/openid-configuration";

            var manager = new ConfigurationManager<OpenIdConnectConfiguration>(discoAddress);
            config = await manager.GetConfigurationAsync();
        }

        private void GetValuesBasedOnType(IEnumerable requestQuery, ref string code, ref string returnedState)
        {
            Type queryType = requestQuery.GetType();
            if (queryType.Equals(typeof(ReadableStringCollection)))
            {
                var enumerator = requestQuery.GetEnumerator();
                while (enumerator.MoveNext())
                {
                    KeyValuePair<string, string[]> current = (KeyValuePair<string, string[]>)enumerator.Current;
                    switch (current.Key)
                    {
                        case "code":
                            code = current.Value[0];
                            break;
                        case "state":
                            returnedState = current.Value[0];
                            break;
                    }
                }
            }

            if (queryType.IsSubclassOf(typeof(NameValueCollection)))
            {
                NameValueCollection nvc = requestQuery as NameValueCollection;
                code = nvc["code"];
                returnedState = nvc["state"];
            }
        }

        private async Task FillClaimsAsync(TokenResponse response)
        {
            if (!string.IsNullOrWhiteSpace(response.IdentityToken))
            {
                this.claims = new List<SystemClaims.Claim>();
                this.claims.Clear();

                if (!string.IsNullOrWhiteSpace(response.AccessToken))
                {
                    this.claims.AddRange(await GetUserInfoClaimsAsync(response.AccessToken));

                    this.claims.Add(new SystemClaims.Claim("access_token", response.AccessToken));
                    this.claims.Add(new SystemClaims.Claim("expires_at", (DateTime.UtcNow.ToEpochTime() + response.ExpiresIn).ToDateTimeFromEpoch().ToString()));
                }

                if (!string.IsNullOrWhiteSpace(response.RefreshToken))
                {
                    this.claims.Add(new SystemClaims.Claim("refresh_token", response.RefreshToken));
                }
            }
        }

        private async Task<IEnumerable<SystemClaims.Claim>> GetUserInfoClaimsAsync(string accessToken)
        {
            UserInfoClient client = new UserInfoClient(new Uri(config.UserInfoEndpoint), accessToken);
            
            this.UserInfo = await client.GetAsync();

            var claims = new List<SystemClaims.Claim>();
            if (this.UserInfo.Claims != null)
            {
                this.UserInfo.Claims.ToList().ForEach(ui => claims.Add(new SystemClaims.Claim(ui.Item1, ui.Item2)));
            }

            return claims;
        }

        private string TryGetValue(string propertyName)
        {
            if (this.UserInfo == null || this.UserInfo.JsonObject == null)
                return string.Empty;

            JToken value;
            return this.UserInfo.JsonObject.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
        #endregion
        #endregion
    }
}
