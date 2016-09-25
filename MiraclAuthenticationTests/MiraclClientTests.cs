using System;
using Microsoft.IdentityModel.Protocols;
using Miracl;
using RichardSzalay.MockHttp;
using System.Collections.Specialized;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using NUnit.Framework;

namespace MiraclAuthenticationTests
{
    [TestFixture]
    public class MiraclClientTests
    {
        private const string TokenEndpoint = "http://nothing/token";
        private const string UserEndpoint = "http://nothing/user";
        private const string AuthorizeEndpoint = "http://nothing/authorize";

        [Test]
        public void Test_AuthorizationRequestUrl()
        {
            MiraclClient client = new MiraclClient();
            IsClientClear(client, false);

            // as it's mock, we don't have discovery and have to set the tokenendpoints manually
            if (client.config == null)
            {
                client.config = new OpenIdConnectConfiguration();
                client.config.AuthorizationEndpoint = AuthorizeEndpoint;
            }

            var url = GetRequestUrl(client, "http://nothing").Result;

            Assert.That(url, Is.Not.Null);
            Assert.That(client, Has.Property("State").Not.Null);
            Assert.That(client, Has.Property("Nonce").Not.Null);
        }

        [Test]
        public void Test_AuthorizationRequestUrl_NullUri()
        {
            MiraclClient client = new MiraclClient();
            Assert.That(() => GetRequestUrl(client, null),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("baseUri"));
        }

        [Test]
        public void Test_AuthorizationRequestUrl_InvalidUri()
        {
            MiraclClient client = new MiraclClient();
            Assert.That(() => GetRequestUrl(client, "Not a URI"),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("baseUri"));
        }

        [Test]
        public void Test_ClearUserInfo()
        {
            MiraclClient client = new MiraclClient();
            IsClientClear(client, false);

            // as it's mock, we don't have discovery and have to set the tokenendpoints manually
            if (client.config == null)
            {
                client.config = new OpenIdConnectConfiguration();
                client.config.AuthorizationEndpoint = AuthorizeEndpoint;
            }

            var url = GetRequestUrl(client, "http://nothing").Result;
            Assert.That(url, Is.Not.Null);
            Assert.That(client, Has.Property("State").Not.Null);
            Assert.That(client, Has.Property("Nonce").Not.Null);

            client.ClearUserInfo(false);
            Assert.That(client, Has.Property("State").Not.Null);
            Assert.That(client, Has.Property("Nonce").Not.Null);
            Assert.That(client, Has.Property("Options").Not.Null);
            Assert.That(client, Has.Property("UserId").Null.Or.Property("UserId").Empty);
            Assert.That(client, Has.Property("Email").Null.Or.Property("Email").Empty);
            Assert.That(client.IsAuthorized(), Is.False);

            client.ClearUserInfo();
            IsClientClear(client, false);
        }

        private static async Task<string> GetRequestUrl(MiraclClient client, string baseUri)
        {
            return await client.GetAuthorizationRequestUrlAsync(baseUri, new MiraclAuthenticationOptions { ClientId = "ClientID" });
        }

        [Test]
        public void Test_Authorization()
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

            MiraclClient client = new MiraclClient(options);

            // Inject the handler or client into your application code
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            client.State = nvc["state"];

            // as it's mock, we don't have discovery and have to set the tokenendpoints manually
            if (client.config == null)
            {
                client.config = new OpenIdConnectConfiguration();
                client.config.TokenEndpoint = TokenEndpoint;
                client.config.UserInfoEndpoint = UserEndpoint;
            }

            var response = Task.Run(async () => await client.ValidateAuthorization(nvc, "http://nothing/SigninMiracl")).Result;
            Assert.That(response, Is.Not.Null);
            Assert.That(response, Has.Property("AccessToken").EqualTo("MockToken"));
            Assert.That(response, Has.Property("ExpiresIn").EqualTo(600));
            Assert.That(response, Has.Property("IdentityToken").EqualTo("MockIdToken"));
            Assert.That(response, Has.Property("RefreshToken").EqualTo("MockRefresh"));
            Assert.That(response, Has.Property("TokenType").EqualTo("Bearer"));

            var identity = Task.Run(async () => await client.GetIdentity(response)).Result;
            Assert.That(identity, Is.Not.Null);
            Assert.That(identity, Has.Property("IsAuthenticated").True);
            Assert.That(identity, Has.Property("AuthenticationType").EqualTo("MIRACL"));
            Assert.That(identity, Has.Property("Claims").Not.Null);
            Assert.That(((Claim)(identity.Claims.First())).Type, Is.EqualTo("sub"));
            Assert.That(((Claim)(identity.Claims.First())).Value, Is.EqualTo("noone@miracl.com"));
        }

        private static void IsClientClear(MiraclClient client, bool isAuthorized)
        {
            Assert.That(client, Has.Property("State").Null);
            Assert.That(client, Has.Property("Nonce").Null);
            Assert.That(client, Has.Property("UserId").Null.Or.Property("UserId").Empty);
            Assert.That(client, Has.Property("Email").Null.Or.Property("Email").Empty);
            Assert.That(client.IsAuthorized(), Is.EqualTo(isAuthorized));
        }
    }
}
