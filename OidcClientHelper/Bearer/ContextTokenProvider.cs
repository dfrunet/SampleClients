using System.Threading.Tasks;
using Microsoft.Owin.Security.OAuth;

namespace OidcClientHelper.Bearer
{
    public class ContextTokenProvider : IOAuthBearerAuthenticationProvider
    {
        private readonly IOAuthBearerAuthenticationProvider _inner;

        /// <summary>
        /// Creates a context token provider that wraps a user provided token provider.
        /// </summary>
        /// <param name="inner">The inner token provider</param>
        public ContextTokenProvider(IOAuthBearerAuthenticationProvider inner = null)
        {
            _inner = inner;
        }

        /// <summary>
        /// Invoked before the <see cref="T:System.Security.Claims.ClaimsIdentity" /> is created. Gives the application an
        /// opportunity to find the identity from a different location, adjust, or reject the token.
        /// </summary>
        /// <param name="context">Contains the token string.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> representing the completed operation.
        /// </returns>
        public Task RequestToken(OAuthRequestTokenContext context)
        {
            context.Token = context.OwinContext.Get<string>("oidchelper:tokenvalidation:token");
            return Task.FromResult(0);
        }

        /// <summary>
        /// Called each time a challenge is being sent to the client. By implementing this method the application
        /// may modify the challenge as needed.
        /// </summary>
        /// <param name="context">Contains the default challenge.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> representing the completed operation.
        /// </returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public Task ApplyChallenge(OAuthChallengeContext context)
        {
            if (_inner != null)
            {
                return _inner.ApplyChallenge(context);
            }

            return Task.FromResult(0);
        }

        /// <summary>
        /// Called each time a request identity has been validated by the middleware. By implementing this method the
        /// application may alter or reject the identity which has arrived with the request.
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="T:System.Security.Claims.ClaimsIdentity" />.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> representing the completed operation.
        /// </returns>
        public Task ValidateIdentity(OAuthValidateIdentityContext context)
        {
            if (_inner != null)
            {
                return _inner.ValidateIdentity(context);
            }

            return Task.FromResult(0);
        }
    }
}
