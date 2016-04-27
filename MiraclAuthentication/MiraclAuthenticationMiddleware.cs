using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using System;
using System.Globalization;

namespace Miracl
{
    public class MiraclAuthenticationMiddleware : AuthenticationMiddleware<MiraclAuthenticationOptions>
    {
        private readonly MiraclClient client;
        private readonly ILogger logger;

        /// <summary>
        /// Initializes a <see cref="MiraclOAuth2AuthenticationMiddleware"/>
        /// </summary>
        /// <param name="next">The next middleware in the OWIN pipeline to invoke</param>
        /// <param name="app">The OWIN application</param>
        /// <param name="options">Configuration options for the middleware</param>
        public MiraclAuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
            MiraclAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ClientId))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "Parameter {0} must be provided!", "ClientId"));
            }

            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "Parameter {0} must be provided!", "ClientSecret"));
            }

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(MiraclAuthenticationMiddleware).FullName, options.AuthenticationType);
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            client = new MiraclClient();
            logger = app.CreateLogger<MiraclAuthenticationMiddleware>();
        }

        /// <summary>
        /// Provides the <see cref="AuthenticationHandler"/> object for processing authentication-related requests.
        /// </summary>
        /// <returns>An <see cref="AuthenticationHandler"/> configured with the <see cref="MiraclAuthenticationOptions"/> supplied to the constructor.</returns>
        protected override AuthenticationHandler<MiraclAuthenticationOptions> CreateHandler()
        {
            return new MiraclAuthenticationHandler(client, logger);
        }
    }
}
