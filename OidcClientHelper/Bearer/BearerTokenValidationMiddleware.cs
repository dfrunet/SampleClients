using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Builder;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.OAuth;
using Owin;
using AppFunc = System.Func<System.Collections.Generic.IDictionary<string, object>, System.Threading.Tasks.Task>;

namespace OidcClientHelper.Bearer
{
    public class BearerTokenValidationMiddleware
    {
        private readonly AppFunc _next;
        private readonly Lazy<AppFunc> _localValidationFunc;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="BearerTokenValidationMiddleware" /> class.
        /// </summary>
        /// <param name="next">The next middleware.</param>
        /// <param name="app">The app builder.</param>
        /// <param name="options">The options.</param>
        public BearerTokenValidationMiddleware(AppFunc next, IAppBuilder app, Lazy<OAuthBearerAuthenticationOptions> options)
        {
            _next = next;
            _logger = app.CreateLogger<BearerTokenValidationMiddleware> ();


            _localValidationFunc = new Lazy<AppFunc>(() =>
            {
                var localBuilder = app.New();
                localBuilder.UseOAuthBearerAuthentication(options.Value);
                localBuilder.Run(ctx => next(ctx.Environment));
                return localBuilder.Build();

            }, LazyThreadSafetyMode.PublicationOnly);

        }

        /// <summary>
        /// Invokes the middleware.
        /// </summary>
        /// <param name="environment">The environment.</param>
        /// <returns></returns>
        public async Task Invoke(IDictionary<string, object> environment)
        {
            var context = new OwinContext(environment);

            var token = GetToken(context);

            if (token == null)
            {
                await _next(environment);
                return;
            }

            context.Set("oidchelper:tokenvalidation:token", token);

            // seems to be a JWT
            if (token.Contains('.'))
            {
                // see if local validation is setup
                if (_localValidationFunc != null)
                {
                    await _localValidationFunc.Value(environment);
                    return;
                }

                _logger.WriteWarning("No validator configured for JWT token");
            }

            await _next(environment);
        }

        private string GetToken(OwinContext context)
        {
            // find token in default location
            string requestToken = null;
            string authorization = context.Request.Headers.Get("Authorization");
            if (!string.IsNullOrEmpty(authorization))
            {
                if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    requestToken = authorization.Substring("Bearer ".Length).Trim();
                }
            }

            return requestToken;
        }
    }
}
