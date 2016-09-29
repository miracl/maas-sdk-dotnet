# maas-sdk-dotnet

[![Master Build Status](https://secure.travis-ci.org/miracl/maas-sdk-dotnet.png?branch=master)](https://travis-ci.org/miracl/maas-sdk-dotnet?branch=master)
[![Master Coverage Status](https://coveralls.io/repos/miracl/maas-sdk-dotnet/badge.svg?branch=master&service=github)](https://coveralls.io/github/miracl/maas-sdk-dotnet?branch=master)

* **category**:    SDK
* **copyright**:   2016 MIRACL UK LTD
* **license**:     ASL 2.0 - http://www.apache.org/licenses/LICENSE-2.0
* **link**:        https://github.com/miracl/maas-sdk-dotnet

## Description

.NET version of the Software Development Kit (SDK) for MPin-As-A-Service (MAAS).

## Setup

1. Download or Clone the project
1. Open `Authentication.sln` with Visual Studio and build
1. Reference the `MiraclAuthentication` project in your ASP.NET project so you could authenticate to the MIRACL server

# Miracl API

## Details and usage for authentication

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
<script src="http://demo.dev.miracl.net/mpin/mpad.js" data-authurl="@ViewBag.AuthorizationUri" data-element="btmpin"></script>
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

Replace `CLIENT_ID` and `CLIENT_SECRET` in the `web.config` file with your valid credential data from the MIRACL server. `baseUri` which is passed to the `MiraclClient.GetAuthorizationRequestUrlAsync` method should be the uri of your web application.
Note that the redirect uri, if not explicitly specified in the `MiraclAuthenticationOptions`, is constructed as `baseUri\SigninMiracl` (the default value of the `CallbackPath` property is `\SigninMiracl`) and it should be passed to the MIRACL server when requiring authentication credential.

* `MiraclAuthenticationApp` demonstrates the usage of `MiraclClient` to authenticate to the MIRACL server

## MIRACL .NET SDK Reference

 MIRACL .NET SDK library is based on the following libraries:

* [IdentityModel](https://github.com/IdentityModel/IdentityModel)
* [Microsoft.IdentityModel.Protocol.Extensions](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet)
* [Microsoft.Owin.Security](http://www.nuget.org/packages/Microsoft.Owin.Security/)

