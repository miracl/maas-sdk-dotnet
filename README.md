# MIRACL .NET SDK

.NET library to connect to an [OpenID Connect](http://openid.net/connect/faq/) server;

## Setup

1. Download or Clone the project
1. Open `Authentication.sln` with Visual Studio and build 
1. Reference the `MiraclAuthentication` project in your ASP.NET project so you could authenticate to the MIRACL server

# Miracl API

## Details and usage for manual authentication

All interaction with API happens through `MiraclClient` object. Each application needs to construct an instance of `MiraclClient`.

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

If the user is not authorized, (s)he should be redirected to the URL returned by `client.GetAuthorizationRequestUrl(baseUri)`. After redirect and user interaction with the MIRACL server, user will be sent to the `redirect uri` defined at creation of the application in the server. Note that the redirect uri should be the same as the one used by the `MiraclClient` object (constructed by the baseUri + `CallbackPath` value of the `MiraclAuthenticationOptions' object).

To complete the authorization the query of the received request should be passed to `client.ValidateAuthorization(Request.QueryString)`. This method will return `null` if user denied authorization or a response with the access token if authorization succeeded. 

### Status check and user data

To check if the user has token use `client.IsAuthorized()`. If so, `client.UserId` and `client.Email` will return additional user data and `client.GetIdentity(tokenResponse)` returns the claims-based identity for granting a user to be signed in. 
If `null` is returned, the user is not authenticated or the token is expired and client needs to be authorized once more to access required data.

Use `client.ClearUserInfo(false)` to drop user identity data.

Use `client.ClearUserInfo()` to clear user authorization status.

## External authentication

To add an external authentication to your application the only thing you should do is adding the following lines in your Startup class:

```
app.UseMiraclAuthentication(new MiraclAuthenticationOptions
	{
		ClientId = "CLIENT_ID",
		ClientSecret = "CLIENT_SECRET"
	});
```


## Samples

Replace `CLIENT_ID` and `CLIENT_SECRET` with valid data from https://m-pin.my.id/protected . `baseUri` should be the uri of your web application. 

* `ManualAuthenticationApp` demonstates using the `MiraclClient` object to authenticate manually to the MIRACL server
* `ExternalAuthenticationApp` demonstates authentication using the external MIRACL service.

