using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Specialized;
using Miracl;
using System.Net;
using System.Text;
using System.IO;
using NSubstitute;

namespace MiraclAuthenticationTests
{
    [TestClass]
    public class MiraclClientTests
    {
        private static MiraclClient Client = new MiraclClient();

        [TestMethod]
        public async void TestAuthorizationRequestUrl()
        {
            IsClientClear(false);
            var url = await Client.GetAuthorizationRequestUrlAsync("http://nothing.com", new MiraclAuthenticationOptions { ClientId = "ClientID" });
            Assert.IsNotNull(url);
            Assert.IsNotNull(Client.State);
            Assert.IsNotNull(Client.Nonce);
        }
        
        [TestMethod]
        public async void TestClearUserInfo()
        {
            IsClientClear(false);
            var url = await Client.GetAuthorizationRequestUrlAsync("http://nothing.com", new MiraclAuthenticationOptions { ClientId = "ClientID" });
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

        [TestMethod]
        public async void TestValidateAuthorization()
        {
            //var url = Client.GetAuthorizationRequestUrl();

            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";

            IdentityModel.Client.TokenResponse tokenResponse = await Client.ValidateAuthorization(nvc, new MiraclAuthenticationOptions { ClientSecret = "MockSecret", ClientId = "MockClient" });

            Assert.IsNotNull(tokenResponse);

            var identity = await Client.GetIdentity(tokenResponse);
            Assert.IsNotNull(identity);
            Assert.IsNotNull(Client.UserId);
            Assert.IsNotNull(Client.Email);
            Assert.IsTrue(Client.IsAuthorized());
            
            Client.ClearUserInfo(true);
            IsClientClear(false);





            //Arrange
            var expected = "response content";
            var expectedBytes = Encoding.UTF8.GetBytes(expected);
            var responseStream = new MemoryStream();
            responseStream.Write(expectedBytes, 0, expectedBytes.Length);
            responseStream.Seek(0, SeekOrigin.Begin);

            var response = Substitute.For<HttpWebResponse>();
            response.GetResponseStream().Returns(responseStream);

            var request = Substitute.For<HttpWebRequest>();
            request.GetResponse().Returns(response);

            var factory = Substitute.For<IHttpWebRequestFactory>();
            factory.Create(Arg.Any<string>()).Returns(request);

            //Act
            var actualRequest = factory.Create("http://www.google.com");
            actualRequest.Method = WebRequestMethods.Http.Get;

            string actual;

            using (var httpWebResponse = (HttpWebResponse)actualRequest.GetResponse())
            {
                using (var streamReader = new StreamReader(httpWebResponse.GetResponseStream()))
                {
                    actual = streamReader.ReadToEnd();
                }
            }

            // assert
            Assert.AreEqual(expected, actual);


        }

        [TestMethod]
        public void TestGetIdentity()
        {
        }

        //[TestMethod]
        //public async void LoginTest()
        //{
        //    IsClientClear(false);

        //    var url = Client.GetAuthorizationRequestUrl("http://nothing.com", new MiraclAuthenticationOptions { ClientId = "xsbbrio6luyyk" });
        //    Assert.IsNotNull(url);
        //    Assert.IsNotNull(Client.State);
        //    Assert.IsNotNull(Client.Nonce);

        //    WebRequest request = WebRequest.Create(url);
        //    WebResponse response = request.GetResponse();
        //    Assert.IsTrue(((HttpWebResponse)response).StatusCode == HttpStatusCode.OK);
        //    Assert.IsNotNull(response.ResponseUri);
        //    Assert.IsNotNull(response.ResponseUri.Query[0]);

        //    //// Get the stream containing content returned by the server.
        //    //Stream dataStream = response.GetResponseStream();
        //    //// Open the stream using a StreamReader for easy access.
        //    //StreamReader reader = new StreamReader(dataStream);
        //    //// Read the content.
        //    //string responseFromServer = reader.ReadToEnd();


        //    NameValueCollection nvc = new NameValueCollection();
        //    nvc["code"] = "OIE3rlAjTtc";
        //    nvc["state"] = "52ca6b1827f54fd1adfe99e3c8431b0d";

        //    IdentityModel.Client.TokenResponse tokenResponse = await Client.ValidateAuthorization(nvc,
        //        new MiraclAuthenticationOptions { AuthenticationType = "Cookies", ClientSecret = "ghp0ofORGoh4ikFUHIDwf7X5RsDA0RwXhppncMG8NRE", ClientId = "xsbbrio6luyyk" });

        //    var identity = await Client.GetIdentity(tokenResponse);
        //    Assert.IsNotNull(identity);
        //    Assert.IsNotNull(Client.UserId);
        //    Assert.IsNotNull(Client.Email);
        //    Assert.IsTrue(Client.IsAuthorized());


        //    Client.ClearUserInfo(true);
        //    IsClientClear(false);
        //}

        private static void IsClientClear(bool isAuthorized)
        {
        //    if (includingAuth)
        //    {
        //        this.State = null;
        //        this.Nonce = null;
        //        this.Options = null;
        //    }

        //    this.RedirectUrl = null;
        //    this.UserInfo = null;
        //    this.Identity = null;
        //    this.AccessTokenResponse = null;



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
    
    public interface IHttpWebRequestFactory
    {
        //IHttpWebRequest Create(string uri);
        HttpWebRequest Create(string uri);
    }
}
