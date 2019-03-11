using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;
using SecurityKey = Microsoft.IdentityModel.Tokens.SecurityKey;
using SecurityToken = Microsoft.IdentityModel.Tokens.SecurityToken;

namespace OidcClientHelper.Bearer
{
    /// <summary>
    /// Extension methods for using <see cref="T:Microsoft.Owin.Security.OpenIdConnect.OpenIdConnectAuthenticationMiddleware"/>
    /// </summary>
    public static class AuthenticationExtensions
    {
        
        public static IAppBuilder UseCustomBearerTokenAuthentication(this IAppBuilder app, BearerTokenAuthenticationOptions options)
        {
            if (app == null) throw new ArgumentNullException("app");
            if (options == null) throw new ArgumentNullException("options");

            var loggerFactory = app.GetLoggerFactory();
            var middlewareOptions = ConfigureLocalValidation(options, loggerFactory);


            app.Use<BearerTokenValidationMiddleware>(app, middlewareOptions);

            //if (options.RequiredScopes.Any())
            //{
            //    var scopeOptions = new ScopeRequirementOptions
            //    {
            //        AuthenticationType = options.AuthenticationType,
            //        RequiredScopes = options.RequiredScopes
            //    };

            //    app.Use<ScopeRequirementMiddleware>(scopeOptions);
            //}


            app.UseStageMarker(PipelineStage.Authenticate);

            return app;
        }


        internal static Lazy<OAuthBearerAuthenticationOptions> ConfigureLocalValidation(
            BearerTokenAuthenticationOptions options, ILoggerFactory loggerFactory)
        {
            return new Lazy<OAuthBearerAuthenticationOptions>(() =>
            {
                // use discovery endpoint
                if (string.IsNullOrWhiteSpace(options.Authority))
                {
                    throw new Exception("Either set IssuerName and SigningCertificate - or Authority");
                }

                var discoveryEndpoint = options.Authority.EnsureTrailingSlash();
                discoveryEndpoint += ".well-known/openid-configuration";

                IIssuerSecurityKeyProvider issuerProvider = new DiscoveryDocumentIssuerSecurityKeyProvider(
                    discoveryEndpoint,
                    options,
                    loggerFactory);

                var valParams = new TokenValidationParameters
                {
                    NameClaimType = options.NameClaimType,
                    RoleClaimType = options.RoleClaimType
                };

                valParams.IssuerSigningKeyResolver = ResolveRsaKeys;
                valParams.ValidateAudience = false;


                var tokenFormat = new JwtFormat(valParams, issuerProvider);

                var bearerOptions = new OAuthBearerAuthenticationOptions
                {
                    AccessTokenFormat = tokenFormat,
                    AuthenticationMode = options.AuthenticationMode,
                    AuthenticationType = options.AuthenticationType,
                    Provider = new ContextTokenProvider(options.TokenProvider)
                };

                return bearerOptions;

            }, LazyThreadSafetyMode.PublicationOnly);
        }


        //string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameter
        private static IEnumerable<SecurityKey> ResolveRsaKeys(
            string token,
            SecurityToken securityToken,
            string kid,
            TokenValidationParameters validationParameters)
        {
            //string id = null;
            //foreach (var keyId in keyIdentifier)
            //{
            //    var nk = keyId as NamedKeySecurityKeyIdentifierClause;
            //    if (nk != null)
            //    {
            //        id = nk.Id;
            //        break;
            //    }
            //}

            //if (id == null) return null;

            var keys = validationParameters.IssuerSigningKeys.Where(it => it.KeyId == kid);
            //if (issuerToken == null) return null;

            return keys;
        }
    }

    public static class utils
    {

        public static string EnsureTrailingSlash(this string input)
        {
            if (!input.EndsWith("/"))
            {
                return input + "/";
            }

            return input;
        }
    }


}
