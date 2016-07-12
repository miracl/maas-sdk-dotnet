using Microsoft.IdentityModel.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Miracl;
using RichardSzalay.MockHttp;
using System.Collections.Specialized;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MiraclAuthenticationTests
{
    [TestClass]
    public class MiraclClientTests
    {
        private static MiraclClient Client = new MiraclClient();
        private const string TokenEndpoint = "http://nothing/token";
        private const string UserEndpoint = "http://nothing/user";
        private const string AuthorizeEndpoint = "http://nothing/authorize";

        [TestMethod]
        public void TestAuthorizationRequestUrl()
        {
            Client = new MiraclClient();
            IsClientClear(false);

            // as it's mock, we don't have discovery and have to set the tokenendpoints manually
            if (Client.config == null)
            {
                Client.config = new OpenIdConnectConfiguration();
                Client.config.AuthorizationEndpoint = AuthorizeEndpoint;
            }

            var url = GetRequestUrl("http://nothing").Result;
            Assert.IsNotNull(url);
            Assert.IsNotNull(Client.State);
            Assert.IsNotNull(Client.Nonce);
        }

        [TestMethod]
        public void TestClearUserInfo()
        {
            Client = new MiraclClient();
            IsClientClear(false);

            // as it's mock, we don't have discovery and have to set the tokenendpoints manually
            if (Client.config == null)
            {
                Client.config = new OpenIdConnectConfiguration();
                Client.config.AuthorizationEndpoint = AuthorizeEndpoint;
            }

            var url = GetRequestUrl("http://nothing").Result;
            Assert.IsNotNull(url);
            Assert.IsNotNull(Client.State);
            Assert.IsNotNull(Client.Nonce);

            Client.ClearUserInfo(false);
            Assert.IsNotNull(Client.State);
            Assert.IsNotNull(Client.Nonce);
            Assert.IsNotNull(Client.Options);
            Assert.IsTrue(string.IsNullOrEmpty(Client.UserId));
            Assert.IsTrue(string.IsNullOrEmpty(Client.Email));
            Assert.IsFalse(Client.IsAuthorized());

            Client.ClearUserInfo();
            IsClientClear(false);
        }

        private static async Task<string> GetRequestUrl(string baseUri)
        {
            return await Client.GetAuthorizationRequestUrlAsync(baseUri, new MiraclAuthenticationOptions { ClientId = "ClientID" });
        }

        [TestMethod]
        public void TestAuthorization()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"MockIdToken\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"sub\":\"noone@miracl.com\"}");

            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions
            {
                ClientId = "MockClient",
                ClientSecret = "MockSecret",
                BackchannelHttpHandler = mockHttp
            };

            Client = new MiraclClient(options);

            // Inject the handler or client into your application code            
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            Client.State = nvc["state"];

            // as it's mock, we don't have discovery and have to set the tokenendpoints manually
            if (Client.config == null)
            {
                Client.config = new OpenIdConnectConfiguration();
                Client.config.TokenEndpoint = TokenEndpoint;
                Client.config.UserInfoEndpoint = UserEndpoint;
            }

            var response = Task.Run(async () => await Client.ValidateAuthorization(nvc, "http://nothing/SigninMiracl")).Result;
            Assert.IsNotNull(response);
            Assert.IsTrue(response.AccessToken.Equals("MockToken"));
            Assert.IsTrue(response.ExpiresIn.Equals(600));
            Assert.IsTrue(response.IdentityToken.Equals("MockIdToken"));
            Assert.IsTrue(response.RefreshToken.Equals("MockRefresh"));
            Assert.IsTrue(response.TokenType == "Bearer");

            var identity = Task.Run(async () => await Client.GetIdentity(response)).Result;
            Assert.IsNotNull(identity);
            Assert.IsTrue(identity.IsAuthenticated);
            Assert.IsTrue(identity.AuthenticationType.Equals("MIRACL"));
            Assert.IsNotNull(identity.Claims);
            Assert.IsTrue(((Claim)(identity.Claims.ElementAt(0))).Type.Equals("sub"));
            Assert.IsTrue(((Claim)(identity.Claims.ElementAt(0))).Value.Equals("noone@miracl.com"));
        }

        private static void IsClientClear(bool isAuthorized)
        {
            Assert.IsNull(Client.Nonce);
            Assert.IsNull(Client.State);
            Assert.IsTrue(string.IsNullOrEmpty(Client.UserId));
            Assert.IsTrue(string.IsNullOrEmpty(Client.Email));
            if (isAuthorized)
                Assert.IsTrue(Client.IsAuthorized());
            else
                Assert.IsFalse(Client.IsAuthorized());
        }
    }
}
