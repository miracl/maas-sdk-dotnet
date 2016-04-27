namespace Miracl
{
    internal static class Constants
    {
        internal const string DefaultAuthenticationType = "MIRACL";
        internal const string CallbackString = "/SigninMiracl";
        internal const string TokenEndpoint = "https://m-pin.my.id/c2id/token"; // "http://mpinaas-demo.miracl.net:8001/oidc/token";
        internal const string UserInfoEndpoint = "https://m-pin.my.id/c2id/userinfo";  // "http://mpinaas-demo.miracl.net:8001/oidc/userinfo";
        internal const string AuthorizeEndpoint = "https://m-pin.my.id/abstractlogin"; //"http://mpinaas-demo.miracl.net:8001/authorize";
    }
}
