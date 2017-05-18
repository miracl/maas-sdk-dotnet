using System;
using Microsoft.IdentityModel.Protocols;
using Miracl;
using RichardSzalay.MockHttp;
using System.Collections.Specialized;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using NUnit.Framework;
using Microsoft.Owin.Security.DataHandler;
using System.IdentityModel;

namespace MiraclAuthenticationTests
{
    [TestFixture]
    public class MiraclClientTests
    {
        private const string Endpoint = "https://api.dev.miracl.net";
        private const string TokenEndpoint = "https://api.dev.miracl.net/oidc/token";
        private const string UserEndpoint = "https://api.dev.miracl.net/oidc/userinfo";
        private const string AuthorizeEndpoint = "https://api.dev.miracl.net/authorize";
        private const string CertUri = "https://api.dev.miracl.net/oidc/certs";
        private const string ValidClientId = "gnuei07bcyee8";
        private const string ValidClientSecret = "q0Hog6cY2pAt3V-0MPXgRfcM9FTNT5gFGr7JvxRXce4";
        private const string ValidAccessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJjaWQiOiJnbnVlaTA3YmN5ZWU4IiwiZXhwIjoxNDkzMDE2NDk5LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIiwiZW1haWwiXSwic3ViIjoicGV0eWEua29sZXZhQG1pcmFjbC5jb20ifQ.MKPhkQ6-QbPIuD68cfy6QmuqelFUs1yUmW2dZn3ovjC8BkdCdgzRzysAvdTQCGe8F-WRTIAdmY00rXmC-z4_VVG1yESdOP2eCOD7zFmIXF9m5OTKMJJEaG6SOUoko5jypohmDk4MuLjOvfMOhXQfWKqLxkliMmM2e8J1FjSY7sF6Azg0Pq_mqK-mznIofbzR7tnA22XmlF_GRqYyoRpUEtkzU2ydoU9oGSJrwtwTeN1vXlzEwSvj65mVkuP4dIqJ5fmYstgTyKlzkwe8wFDHhB3Px-89lh5JRYKoY0nbDIUOc0RA0dKFnnFX3P0Cp9kp2QOwXYdRLmdhvhn7IeJjjw";
        private const string ValidIdToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJhbXIiOlsidG9rZW4iXSwiYXVkIjoiZ251ZWkwN2JjeWVlOCIsImV4cCI6MTQ5MzAxNjc3NSwiaWF0IjoxNDkzMDE1ODc1LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsIm5vbmNlIjoiODBmY2Q1M2QzNTc2NjIxZGE2MjNlMWZkYmU2YzdjNTE0MTZhOTc1YTNlNTM4OThjY2IwYmRlZWIwODRiZTQyZiIsInN1YiI6InBldHlhLmtvbGV2YUBtaXJhY2wuY29tIn0.CTQu9bx7vCV6pZvtDhEJTFjeasMJoZtbq93vFj2nwVODaGj5Ajp9ZYZvhD7eeYtOBzBH0rOAjNc_348bZXjiqi3IdpEMCTiQz0dPqxTlywUjwM0HCMQ0C0TIwUh4f8Os0rthF1a1yYy_WgL7FgFsmb12xwTwt_TXrKHqbHXV-eX8ip0GCQgao9B1VC3Jj4NEfEXuUSq2nexEx-p_H9LgqbNBro3i_kPoP7C3wfiSFS30qDDUKZLp3SeW90-ErcNQKmU7rukvujeCpeziYlycLyeRTPVmAOTMEyO4ABQyk4KTl_w9P2O8AXW6a2B7nfjGAQGVT_m9Z_56yzgJoJ9KRg";
        private const string Nonce = "80fcd53d3576621da623e1fdbe6c7c51416a975a3e53898ccb0bdeeb084be42f";
        private const string Keys = "{\"keys\": [ {\"kty\": \"RSA\",\"use\": \"sig\",\"kid\": \"31-07-2016\",\"n\": \"kwBfKdZTTt8dD-o1VPXKCH4hi28-KUMsPy7OYBrk4lgCd1EHZCVvZdKkcjPW0kGjC3vuee7C5v516Siids684n_V8mznvLwNFGKJ3fdiubkxKc5cpgPrxH86uHr0sU-ACoWhkW3KjFKBb-WNYSqcNxKaXI-dcKJtAaZNqnbwjf0_fkWAEsrPYyMPeYt6AjX2vDhqu4a4zrclKiy2ngEkZ91GwrvATX5UrooefIuNc2PRC-Y7mccvcm9cK0V6xLeWovivWX-GTHwMuPymIJGyDqo-6NRkqv6sl-QIFEzohQd3jSLUyt71u8lqgOlfW2JN7T_HOOkg_ibq6u-k94HJQw\",\"e\": \"AQAB\"}]}";
        
        private void AddConfigData(MiraclClient client, bool addKeys = true)
        {
            // as it's mock, we don't have discovery and have to set the tokenendpoints manually
            if (client.config == null)
            {
                client.config = new OpenIdConnectConfiguration();
                client.config.AuthorizationEndpoint = AuthorizeEndpoint;
                client.config.TokenEndpoint = TokenEndpoint;
                client.config.UserInfoEndpoint = UserEndpoint;
                client.config.Issuer = Endpoint;
                client.Nonce = Nonce;
                if (addKeys)
                {
                    client.config.JsonWebKeySet = new JsonWebKeySet(Keys);
                }
            }
        }

        private static void IsClientClear(MiraclClient client, bool isAuthorized)
        {
            Assert.That(client, Has.Property("State").Null);
            Assert.That(client, Has.Property("Nonce").Null);
            Assert.That(client, Has.Property("UserId").Null.Or.Property("UserId").Empty);
            Assert.That(client, Has.Property("Email").Null.Or.Property("Email").Empty);
            Assert.That(client.IsAuthorized(), Is.EqualTo(isAuthorized));
        }

        [Test]
        public void Test_AuthorizationRequestUrl()
        {
            MiraclClient client = new MiraclClient();
            IsClientClear(client, false);
            AddConfigData(client);

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
        public void Test_AuthorizationRequestUr_NoOptions()
        {
            MiraclClient client = new MiraclClient();
            client.config = new OpenIdConnectConfiguration();
            Assert.That(() => Task.Run(async () => await client.GetAuthorizationRequestUrlAsync(AuthorizeEndpoint)),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("MiraclAuthenticationOptions should be set!"));
        }

        [Test]
        public void Test_ClearUserInfo()
        {
            MiraclClient client = new MiraclClient();
            IsClientClear(client, false);
            AddConfigData(client);

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
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"sub\":\"noone@miracl.com\"}");

            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            options.ClientId = ValidClientId;
            options.ClientSecret = ValidClientSecret;
            options.BackchannelTimeout = TimeSpan.FromMinutes(1);
            options.BackchannelHttpHandler = mockHttp;
            options.PlatformAPIAddress = Endpoint;
            options.CallbackPath = new Microsoft.Owin.PathString("/CallbackPath");
            options.StateDataFormat = new PropertiesDataFormat(null);

            MiraclClient client = new MiraclClient(options);
            Assert.That(client.Options.PlatformAPIAddress, Is.EqualTo(Endpoint));
            Assert.That(client.Options.StateDataFormat, Is.TypeOf(typeof(PropertiesDataFormat)));

            // Inject the handler or client into your application code
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            client.State = nvc["state"];
            client.Nonce = Nonce;
            AddConfigData(client);

            var response = Task.Run(async () => await client.ValidateAuthorization(nvc, "http://nothing/login")).Result;
            Assert.That(response, Is.Not.Null);
            Assert.That(response, Has.Property("AccessToken").EqualTo("MockToken"));
            Assert.That(response, Has.Property("ExpiresIn").EqualTo(600));
            Assert.That(response, Has.Property("IdentityToken").EqualTo(ValidIdToken));
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

        [Test]
        public void Test_ValidateAuthorization_NullRequestQuery()
        {
            Assert.That(() => new MiraclClient().ValidateAuthorization(null),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("requestQuery"));
        }

        [Test]
        public void Test_ValidateAuthorization_NoOptions()
        {
            MiraclClient client = new MiraclClient();
            // Inject the handler or client into your application code
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            client.State = nvc["state"];

            Assert.That(() => new MiraclClient().ValidateAuthorization(nvc, "http://nothing/SigninMiracl"),
                Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void Test_ValidateAuthorization_MissingCode()
        {
            NameValueCollection nameValueCollection;

            nameValueCollection = new NameValueCollection();
            nameValueCollection[Constants.State] = "state";

            Assert.That(() => new MiraclClient(new MiraclAuthenticationOptions()).ValidateAuthorization(nameValueCollection),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("requestQuery"));
        }

        [Test]
        public void Test_ValidateAuthorization_MissingState()
        {
            NameValueCollection nameValueCollection;
            nameValueCollection = new NameValueCollection();
            nameValueCollection[Constants.Code] = "code";

            Assert.That(() => new MiraclClient(new MiraclAuthenticationOptions()).ValidateAuthorization(nameValueCollection),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("requestQuery"));
        }

        [Test]
        public void Test_ValidateAuthorization_InvalidState()
        {
            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            MiraclClient client = new MiraclClient(options);
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            client.State = "DifferentState";

            Assert.That(() => client.ValidateAuthorization(nvc, "http://nothing/SigninMiracl"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid state!"));
        }

        [Test]
        public void Test_ValidateAuthorization_NoRedirectUrl()
        {
            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            MiraclClient client = new MiraclClient(options);
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            client.State = nvc["state"];

            Assert.That(() => client.ValidateAuthorization(nvc),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Empty redirect uri!"));
        }

        [Test]
        public void Test_ValidateAuthorization_UseCallbackUrl()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken +"\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"sub\":\"noone@miracl.com\"}");
            
            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            options.ClientId = ValidClientId;
            options.ClientSecret = ValidClientSecret;
            options.BackchannelHttpHandler = mockHttp;
            MiraclClient client = new MiraclClient(options);
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            client.State = nvc["state"];
            client.callbackUrl = "/CallbackPath";
            AddConfigData(client);

            var response = client.ValidateAuthorization(nvc).Result;
            Assert.That(response, Is.Not.Null);
        }

        [Test]
        public void Test_ValidateAuthorization_Error()
        {
            NameValueCollection nvc = new NameValueCollection();
            nvc[Constants.State] = "state";
            nvc[Constants.Error] = "some error";

            Assert.That(() => new MiraclClient(new MiraclAuthenticationOptions()).ValidateAuthorization(nvc),
                Throws.TypeOf<Exception>().And.Message.EqualTo("some error"));
        }
        
        [Test]
        public void Test_ValidateAuthorizationCode()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");

            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            options.ClientId = ValidClientId;
            options.ClientSecret = ValidClientSecret;
            options.BackchannelHttpHandler = mockHttp;
            MiraclClient client = new MiraclClient(options);
            client.callbackUrl = "/CallbackPath";
            AddConfigData(client, false);

            Assert.That(() => client.ValidateAuthorizationCode("MockCode", "wrong@mail.me"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("No Keys found in the config"));

            // add keys 
            client.config.JsonWebKeySet = new JsonWebKeySet("{\"keys\": [ {\"kty\": \"RSA\",\"use\": \"sig\",\"kid\": \"31-07-2016\",\"n\": \"kwBfKdZTTt8dD-o1VPXKCH4hi28-KUMsPy7OYBrk4lgCd1EHZCVvZdKkcjPW0kGjC3vuee7C5v516Siids684n_V8mznvLwNFGKJ3fdiubkxKc5cpgPrxH86uHr0sU-ACoWhkW3KjFKBb-WNYSqcNxKaXI-dcKJtAaZNqnbwjf0_fkWAEsrPYyMPeYt6AjX2vDhqu4a4zrclKiy2ngEkZ91GwrvATX5UrooefIuNc2PRC-Y7mccvcm9cK0V6xLeWovivWX-GTHwMuPymIJGyDqo-6NRkqv6sl-QIFEzohQd3jSLUyt71u8lqgOlfW2JN7T_HOOkg_ibq6u-k94HJQw\",\"e\": \"AQAB\"}]}");

            var response = client.ValidateAuthorizationCode("MockCode", "wrong@mail.me").Result;
            Assert.That(response, Is.Null);
            
            response = client.ValidateAuthorizationCode("MockCode", "petya.koleva@miracl.com").Result;
            Assert.That(response, Is.Not.Null);
            Assert.That(response.RefreshToken, Is.EqualTo("MockRefresh"));
            Assert.That(response.AccessToken, Is.EqualTo("MockToken"));

            mockHttp.Clear();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorizationCode("MockCode", "empty@identity.token"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid token data!"));
        }
            
        [Test]
        public void Test_ValidateAuthorization_InvalidNonce()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"\",\"id_token\":\".eyJzdWIiOiJwZXR5YS5rb2xldmFAbWlyYWNsLmNvbSJ9\"}");
            
            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            options.BackchannelHttpHandler = mockHttp;
            MiraclClient client = new MiraclClient(options);
            client.Options.ClientId = "MockClient";
            client.Options.ClientSecret = "MockSecret";
            client.config = new OpenIdConnectConfiguration();
            client.config.TokenEndpoint = TokenEndpoint;

            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            client.State = nvc["state"];
            client.callbackUrl = "/CallbackPath";

            Assert.That(() => client.ValidateAuthorization(nvc),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid nonce!"));
        }

        [Test]
        public void Test_GetIdentity_NullResponse()
        {
            Assert.That(() => new MiraclClient().GetIdentity(null),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("response"));
        }

        [Test]
        public void Test_GetIdentity_NoOptions()
        {
            Assert.That(() => new MiraclClient().GetIdentity(new IdentityModel.Client.TokenResponse("{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"MockIdToken\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}")),
               Throws.TypeOf<InvalidOperationException>().And.Message.EqualTo("No Options for authentication! ValidateAuthorization method should be called first!"));
        }

        [Test]
        public void Test_FillClaimsAsync_NoResponse()
        {
            Assert.That(() => new MiraclClient().FillClaimsAsync(null),
                Throws.TypeOf<ArgumentNullException>().And.Message.Contains("The response, its IdentityToken or AccessToken are null!"));
        }

        [Test]
        public void Test_TryGetValue()
        {
            var client = new MiraclClient();
            client.userInfo = new IdentityModel.Client.UserInfoResponse("{\"sub\":\"noone@miracl.com\"}");
            Assert.That(client.TryGetValue("sub"), Is.EqualTo("noone@miracl.com"));
        }

        [Test]
        public void Test_ParseJwt_InvalidToken()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"InvalidIdToken\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"sub\":\"noone@miracl.com\"}");

            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            options.ClientId = "MockClient";
            options.ClientSecret = "MockSecret";
            options.BackchannelTimeout = TimeSpan.FromMinutes(1);
            options.BackchannelHttpHandler = mockHttp;
            options.PlatformAPIAddress = Endpoint;
            options.CallbackPath = new Microsoft.Owin.PathString("/CallbackPath");
            options.StateDataFormat = new PropertiesDataFormat(null);

            MiraclClient client = new MiraclClient(options);
            Assert.That(client.Options.PlatformAPIAddress, Is.EqualTo(Endpoint));
            Assert.That(client.Options.StateDataFormat, Is.TypeOf(typeof(PropertiesDataFormat)));

            // Inject the handler or client into your application code
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            client.State = nvc["state"];
            client.Nonce = Nonce;
            AddConfigData(client);
            
            Assert.That(() => client.ValidateAuthorization(nvc, "http://nothing/login"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Wrong token data!"));

            mockHttp.Clear();
            var noNonce = "33.eyJhbGciOiJSUzI1NiIsImtpZCI6IjAxLTA4LTIwMTYifQ";
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + noNonce + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorization(nvc, "http://nothing/login"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid nonce!"));


            mockHttp.Clear();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJhbXIiOlsidG9rZW4iXSwiYXVkIjoiZ251ZWkwN2JjeWVlOCIsImV4cCI6MTQ5MzAxNjc3NSwiaWF0IjoxNDkzMDE1ODc1LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsIm5vbmNlIjoiODBmY2Q1M2QzNTc2NjIxZGE2MjNlMWZkYmU2YzdjNTE0MTZhOTc1YTNlNTM4OThjY2IwYmRlZWIwODRiZTQyZiIsInN1YiI6InBldHlhLmtvbGV2YUBtaXJhY2wuY29tIn0" + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorization(nvc, "http://nothing/login"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid token format"));

            mockHttp.Clear();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJhbXIiOlsidG9rZW4iXSwiYXVkIjoiZ251ZWkwN2JjeWVlOCIsImV4cCI6MTQ5MzAxNjc3NSwiaWF0IjoxNDkzMDE1ODc1LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsIm5vbmNlIjoiODBmY2Q1M2QzNTc2NjIxZGE2MjNlMWZkYmU2YzdjNTE0MTZhOTc1YTNlNTM4OThjY2IwYmRlZWIwODRiZTQyZiIsInN1YiI6InBldHlhLmtvbGV2YUBtaXJhY2wuY29tIn0.invalidSignature" + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorization(nvc, "http://nothing/login"),
                Throws.TypeOf<SignatureVerificationFailedException>().And.Message.Contains("Signature validation failed"));
        }
    }
}
