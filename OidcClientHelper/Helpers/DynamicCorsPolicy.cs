using System;
using System.Configuration;
using System.Threading.Tasks;
using System.Web.Cors;
using Microsoft.Owin;
using Microsoft.Owin.Cors;
using OidcClientHelper.Settings;

namespace OidcClientHelper.Helpers
{
    public class DynamicCorsPolicy : ICorsPolicyProvider
    {
        public Task<CorsPolicy> GetCorsPolicyAsync(IOwinRequest request)
        {
            var policy = new CorsPolicy
            {
                AllowAnyMethod = true,
                AllowAnyHeader = true,
                SupportsCredentials = true
            };


            var origin = request.Headers["Origin"];
            if (origin != null && Uri.IsWellFormedUriString(origin, UriKind.Absolute))
            {
                var originUri = new Uri(origin, UriKind.Absolute);
                var refAuthority = originUri.Host.ToLowerInvariant();

                var authorityHost =
                    $"{new Uri(OpenIdConnectAuthentication.Default.Authority).GetComponents(UriComponents.Host, UriFormat.Unescaped)}"
                        .TrimEnd('/');
                int domainIndex = authorityHost.IndexOf('.');
                if (domainIndex > 0)
                    authorityHost = authorityHost.Remove(0, domainIndex + 1);

                if (refAuthority.EndsWith(authorityHost) || String.Equals(ConfigurationManager.AppSettings["cors:allowAny"],
                        bool.TrueString, StringComparison.InvariantCultureIgnoreCase))
                {
                    // returns a url with scheme, host and port(if different than 80/443) without any path or querystring
                    policy.Origins.Add(originUri.GetComponents(UriComponents.SchemeAndServer, UriFormat.SafeUnescaped));
                }
            }
            return Task.FromResult(policy);
        }
    }
}
