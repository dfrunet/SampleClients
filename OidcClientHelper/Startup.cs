using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web.Helpers;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Security.OpenIdConnect;
using OidcClientHelper.Bearer;
using OidcClientHelper.Helpers;
using OidcClientHelper.Settings;
using Owin;
using Task = System.Threading.Tasks.Task;


[assembly: OwinStartup(typeof(OidcClientHelper.Startup))]
namespace OidcClientHelper
{
    public class Startup
    {
        public const string SessionClaimType = "http://schemas.devexternal.com/identity/claims/2011/11/sessionid";
        public const string TenantIdClaimType = "http://schemas.devexternal.com/identity/claims/2011/11/tenantid";

        public const string CultureClaimType = "http://schemas.devexternal.com/identity/claims/2011/11/culture";
        
        public const string SupportedModuleClaimType = "module";

        public const string DefaultLocale = "en-GB";

        private ILogger logger;

        static Startup()
        {
            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;
        }

        static string TenantIdSetting
        {
            get
            {
                try
                {
                    string tenantId = ConfigurationManager.AppSettings["TenantId"];
                    return tenantId;
                }
                catch (Exception ex)
                {
                    return null;
                }
            }
        }

        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap = new Dictionary<string, string>
            {
                {"name", ClaimTypes.Name},
                {"role", ClaimTypes.Role},
                {"email", ClaimTypes.NameIdentifier},
                {"sid", SessionClaimType},
                {"tenantid", TenantIdClaimType},
                {"locale", ClaimTypes.Locality}
            };

            app.Use(async (context, next) =>
            {
                if (Trace.CorrelationManager.ActivityId == Guid.Empty)
                {
                    Trace.CorrelationManager.ActivityId = Guid.NewGuid();
                }

                await next();
            });


            app.UseCors(new CorsOptions() { PolicyProvider = new DynamicCorsPolicy() });

            logger = app.CreateLogger<Startup>();


            app.Use<LogoutMiddleware>(app);


            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);


            //Use https protocol in case of SSL Offload (for OWIN middleware correct reply address generation)
            app.Use(async (context, next) =>
            {
                if (String.Equals(ConfigurationManager.AppSettings["SslOffload"],
                    bool.TrueString, StringComparison.InvariantCultureIgnoreCase))
                {
                    context.Request.Scheme = Uri.UriSchemeHttps;
                }

                await next.Invoke();
            });



            app.Use(async (context, next) =>
            {
                var redirectHost =
                    $"{new Uri(OpenIdConnectAuthentication.Default.RedirectUri).GetComponents(UriComponents.Host, UriFormat.Unescaped)}".TrimEnd('/');
                var redirectHostAndPort =
                    $"{new Uri(OpenIdConnectAuthentication.Default.RedirectUri).GetComponents(UriComponents.HostAndPort, UriFormat.Unescaped)}".TrimEnd('/');
                if (!context.Request.Host.ToString().Equals(redirectHost, StringComparison.Ordinal)
                && !context.Request.Host.ToString().Equals(redirectHostAndPort, StringComparison.Ordinal))
                {
                    context.Request.Host = new HostString(redirectHost);
                }
                var baseRedirectPath =
                    $"/{new Uri(OpenIdConnectAuthentication.Default.RedirectUri).GetComponents(UriComponents.Path, UriFormat.Unescaped)}".TrimEnd('/');
                if (context.Request.PathBase == new PathString(baseRedirectPath) &&
                    !context.Request.PathBase.ToString().Equals(baseRedirectPath, StringComparison.Ordinal))
                {
                    context.Request.PathBase = new PathString(baseRedirectPath);
                }
                await next.Invoke();
            });


            app.UseCustomBearerTokenAuthentication(new BearerTokenAuthenticationOptions()
            {
                Authority = OpenIdConnectAuthentication.Default.Authority,
                AuthenticationMode = AuthenticationMode.Active,
            });

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                CookieManager = new SystemWebChunkingCookieManager(),
                CookiePath =
                    $"/{new Uri(OpenIdConnectAuthentication.Default.RedirectUri).GetComponents(UriComponents.Path, UriFormat.Unescaped)}",
                Provider = new CookieAuthenticationProvider
                {
                    OnValidateIdentity = ctx =>
                    {
                        //Here we mix-into the token a new claim based on request query parameter
                        //if (!ctx.Identity.HasClaim(c => c.Type == EmploymentIdClaimType) && ctx.Request.Query.Any(q => q.Key == "aeid"))
                        //{
                        //    ctx.Identity.AddClaim(new Claim(EmploymentIdClaimType, ctx.Request.Query["aeid"]));
                        //}
                        return Task.FromResult(0);
                    },

                    OnApplyRedirect = ctx =>
                    {
                        if (!ctx.Request.IsAjaxRequest())
                        {
                            ctx.Response.Redirect(ctx.RedirectUri);
                        }
                    }
                },
                ExpireTimeSpan = TimeSpan.FromSeconds(600),
                SlidingExpiration = true
            });

            //tenant check
            //compare the setting in configuration file with the value coming from idp
            app.Use(async (context, next) =>
            {
                if (context.Authentication?.User?.Identity.IsAuthenticated == true &&
                !String.IsNullOrWhiteSpace(TenantIdSetting) &&
                    !String.Equals(context.Authentication.User.FindFirst(TenantIdClaimType)?.Value, TenantIdSetting, StringComparison.InvariantCultureIgnoreCase))
                {
                    context.Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
                    context.Response.Redirect(OpenIdConnectAuthentication.Default.Authority.TrimEnd('/') +
                                              "/home/error?errorId=tenant-mismatch");
                }
                else

                    await next();
            });


           
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions() 
            {
                RequireHttpsMetadata = false,
                //Authority = "http://localhost:5100", //ID Server
                Authority = OpenIdConnectAuthentication.Default.Authority,
                ClientId = OpenIdConnectAuthentication.Default.ClientId, //"spa-client",
                ResponseType = OpenIdConnectAuthentication.Default.ResponseType, //"id_token","id_token code" 
                ClientSecret = OpenIdConnectAuthentication.Default.ClientSecret,
                SignInAsAuthenticationType = Microsoft.AspNet.Identity.DefaultAuthenticationTypes.ApplicationCookie,
                //UseTokenLifetime = false,
                //ProtocolValidator = new OpenIdConnectProtocolValidator()
                //{
                //    NonceLifetime = new TimeSpan(0,0,20,0)
                //    //RequireNonce = false,
                //},
                CookieManager = new SystemWebChunkingCookieManager(),

                TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateAudience = false
                },
                RedirectUri = OpenIdConnectAuthentication.Default.RedirectUri, //URL of website
                Scope = OpenIdConnectAuthentication.Default.Scope,// "openid email roles", //", profile
                PostLogoutRedirectUri = OpenIdConnectAuthentication.Default.RedirectUri, //"http://google.com",
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = notification =>
                    {
                        if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout &&
                            notification.OwinContext.Authentication.User?.Claims.FirstOrDefault(_ => _.Type == "id_token") !=
                            null)
                        {
                            var idTokenHint = notification.OwinContext.Authentication.User.FindFirst("id_token").Value;
                            notification.ProtocolMessage.IdTokenHint = idTokenHint;
                            notification.ProtocolMessage.PostLogoutRedirectUri =
                                notification.OwinContext.Authentication?.AuthenticationResponseRevoke?.Properties?.RedirectUri ??
                                OpenIdConnectAuthentication.Default.RedirectUri;
                        }

                        if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                        {
                            if (notification.Request.IsAjaxRequest() || notification.Request.Uri.OriginalString.IndexOf("/api/", StringComparison.InvariantCultureIgnoreCase)>=0)
                            {
                                var builder = new StringBuilder();
                                builder.AppendLine("Ajax call to restricted content.");
                                builder.AppendLine($" request uri:{notification.Request.Uri}");
                                var headers = notification.Request?.Headers?.Select(x => $"{x.Key}:{String.Join(", ", x.Value)};");
                                if (headers != null) builder.AppendLine($"request headers:");
                                if (headers != null)
                                    foreach (var header in headers)
                                    {
                                        builder.AppendLine(header);
                                    }
                                logger.WriteInformation(builder.ToString());
                                


                                notification.HandleResponse();
                            }
                        }

                        return Task.FromResult(0);
                    },

                    AuthenticationFailed = context =>
                    {
                        //helps to solve some issues of nonce validation with IFrame
                        //most likely this case never occur in normal scenario
                        if (context.Exception.Message.StartsWith("OICE_20004") ||
                            context.Exception.Message.Contains("IDX10311"))
                        {
                            context.SkipToNextMiddleware();
                            return Task.FromResult(0);
                        }

                        context.HandleResponse();

                        logger.WriteError(context.Exception.Message, context.Exception);
                        context.Response.WriteAsync(context.Exception.Message);
                        return Task.FromResult(0);
                    },
                    
                    SecurityTokenValidated = async n =>
                    {
                        var id = n.AuthenticationTicket.Identity;
                        var props = n.AuthenticationTicket.Properties;
                        var t = n.ProtocolMessage.AccessToken;

                        // we want to keep name and roles
                        var email = id.FindFirst(ClaimTypes.NameIdentifier);
                        var sub = id.FindFirst("sub");
                        //var sub = id.FindFirst(JwtClaimTypes.Subject);
                        var roles = id.FindAll(ClaimTypes.Role).Distinct();
                        var locale = id.FindFirst(ClaimTypes.Locality) ?? new Claim(ClaimTypes.Locality, DefaultLocale);

                        var idp = id.FindFirst("idp");
                        var iss = id.FindFirst("iss");
                        var exp = id.FindFirst("exp");
                        //var idp = id.FindFirst(JwtClaimTypes.IdentityProvider);
                        //var iss = id.FindFirst(JwtClaimTypes.Issuer);
                        //var exp = id.FindFirst(JwtClaimTypes.Expiration);
                        //var aud =  id.FindFirst("aud");
                        var sid = id.FindFirst(SessionClaimType);
                        var tid = id.FindFirst(TenantIdClaimType);

                        // create new identity and set name and role claim type
                        var nid = new ClaimsIdentity(
                            id.AuthenticationType,
                            ClaimTypes.NameIdentifier,
                            ClaimTypes.Role);

                        nid.AddClaim(email);
                        nid.AddClaims(roles);
                        nid.AddClaim(idp);
                        nid.AddClaim(iss);
                        //nid.AddClaim(aud);
                        nid.AddClaim(sub);
                        nid.AddClaim(sid);
                        //nid.AddClaim(tid);
                        nid.AddClaim(locale);
                        nid.AddClaim(new Claim(CultureClaimType, locale.Value, locale.ValueType, locale.Issuer));
                        nid.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));
                        if (n.ProtocolMessage.AccessToken != null)
                        {
                            nid.AddClaim(new Claim("token", n.ProtocolMessage.AccessToken));
                            var handler = new JwtSecurityTokenHandler();
                            var tokenS = handler.ReadToken(n.ProtocolMessage.AccessToken) as JwtSecurityToken;
                            foreach (var module in tokenS.Claims.Where(c => c.Type == SupportedModuleClaimType))
                            {
                                nid.AddClaim(module);
                            }
                        }

                        
                        // add some other app specific claim
                        //nid.AddClaim(new Claim("app_specific", "some data"));
                        nid.AddClaim(new Claim(ClaimTypes.Name, email.Value, email.ValueType, email.Issuer));

                        if (n.ProtocolMessage.AccessToken != null)
                        {
                            var delegatedToken = await DelegateAsync(n.ProtocolMessage.AccessToken);
                        }

                        //var timeInTicks = long.Parse(exp.Value) * TimeSpan.TicksPerSecond;
                        //var expTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddTicks(timeInTicks);
                        //n.AuthenticationTicket.Properties.ExpiresUtc = expTime;
                        //n.Response
                        n.AuthenticationTicket = new AuthenticationTicket(
                            nid,
                            n.AuthenticationTicket.Properties);


                        n.AuthenticationTicket.Properties.AllowRefresh = true;
                        n.AuthenticationTicket.Properties.IsPersistent = true;


                        await Task.FromResult(0);
                    }
                }
            });

            app.UseStageMarker(PipelineStage.Authenticate);
        }

        //just an example of delegation
        private async Task<TokenResponse> DelegateAsync(string userToken)
        {
            var payload = new
            {
                token = userToken
            };
            var disco = await new HttpClient().GetDiscoveryDocumentAsync(OpenIdConnectAuthentication.Default.Authority);

            var client = new HttpClient();

            var response = await client.RequestTokenAsync(new TokenRequest
            {
                Address = disco.TokenEndpoint,
                GrantType = "delegation",

                ClientId = "another-svc-client",
                ClientSecret = "some-secret-2019",

                Parameters =
                {
                    { "token", userToken},
                    { "scope", "graph-api graph-api.backend" }
                }
            });
            return response;
            // create token client
            //var client = new TokenClient(disco.TokenEndpoint, "another-svc-client", "some-secret-2019");

            // send custom grant to token endpoint, return response
            //return await client.RequestCustomGrantAsync("delegation", "graph-api graph-api.backend", payload);

        }
    }
}
