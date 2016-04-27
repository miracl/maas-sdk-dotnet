using Owin;
using System;

namespace Miracl
{
    public static class MiraclAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using MIRACL OAuth 2.0
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="clientId">The MIRACL assigned client id</param>
        /// <param name="clientSecret">The MIRACL assigned client secret</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseMiraclAuthentication(
           this IAppBuilder app,
           string clientId,
           string clientSecret)
        {
            return UseMiraclAuthentication(
                app,
                new MiraclAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret
                });
        }

        /// <summary>
        /// Authenticate users using MIRACL OAuth 2.0
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseMiraclAuthentication(this IAppBuilder app, MiraclAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(MiraclAuthenticationMiddleware), app, options);
            return app;
        }
    }
}
