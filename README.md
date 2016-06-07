# MIRACL .NET SDK

.NET library to connect to an [OpenID Connect](http://openid.net/connect/faq/) server;

## Setup

1. Download or Clone the project
1. Open `Authentication.sln` with Visual Studio and build 
1. Reference the `MiraclAuthentication` project in your ASP.NET project so you could authenticate to the MIRACL server

# Miracl API

## Details and usage for manual authentication

All interaction with API happens through a `MiraclClient` object. Each application needs to construct an instance of `MiraclClient`.

### Initialization
To start using Miracl API, `MiraclClient` should be initialized. It can be done when needed or at application startup. `MiraclAuthenticationOptions` class is used to pass the authentication credentials and parameters.

```	
client = new MiraclClient(new MiraclAuthenticationOptions 
{ 
    ClientId = "CLIENT_ID" ,
    ClientSecret = "CLIENT_SECRET"
});
```

`CLIENT_ID` and `CLIENT_SECRET` are obtained from MIRACL server and are unique per application.

### Authorization flow

If the user is not authorized, (s)he should scan the qr barcode with his/her phone app and authorize on the MIRACL server. This could be done as pass the authorize uri to the qr bacode by `ViewBag.AuthorizationUri = client.GetAuthorizationRequestUrl(baseUri)` on the server and use it in the client with the following code:

```	
<a id="btmpin"></a>

@section scripts{
<script src="http://demo.dev.miracl.net/mpin/mpad.js" x-authurl="@ViewBag.AuthorizationUri" x-element="btmpin"></script>
}
```

When the user is being authorized, (s)he is returned to the `redirect uri` defined at creation of the application in the server. The redirect uri should be the same as the one used by the `MiraclClient` object (constructed by the appBaseUri + `CallbackPath` value of the `MiraclAuthenticationOptions` object by default).

To complete the authorization the query of the received request should be passed to `client.ValidateAuthorization(Request.QueryString)`. This method will return `null` if user denied authorization or a response with the access token if authorization succeeded. 

### Status check and user data

To check if the user has token use `client.IsAuthorized()`. If so, `client.UserId` and `client.Email` will return additional user data after `client.GetIdentity(tokenResponse)` is executed which itself returns the claims-based identity for granting a user to be signed in. 
If `null` is returned, the user is not authenticated or the token is expired and client needs to be authorized once more to access required data.

Use `client.ClearUserInfo(false)` to drop user identity data.

Use `client.ClearUserInfo()` to clear user authorization status.

## Samples

Replace `CLIENT_ID` and `CLIENT_SECRET` with valid data from the MIRACL server. `baseUri` should be the uri of your web application. 

* `ManualAuthenticationApp` demonstates using the `MiraclClient` object to authenticate manually to the MIRACL server

## MIRACL .NET SDK Reference

 MIRACL .NET SDK library is based on the following library

* [IdentityModel](https://github.com/IdentityModel/IdentityModel)
* [Microsoft.IdentityModel.Protocol.Extensions](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet)
* [Microsoft.Owin.Security](http://www.nuget.org/packages/Microsoft.Owin.Security/)
