using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Cookies;
using OidcClientHelper.Settings;
using Owin;

namespace OidcClientHelper.Helpers
{
    public class LogoutMiddleware : OwinMiddleware
    {
        private ILogger logger;

        public LogoutMiddleware(OwinMiddleware next, IAppBuilder app) : base(next)
        {
            this.logger = app.CreateLogger<LogoutMiddleware>();
        }

        public override async Task Invoke(IOwinContext context)
        {
            //Console.WriteLine("Begin Request");

            var sid = context.Request.Query.FirstOrDefault(_ => _.Key == "sid");
            if (context.Request.Query.Any(_ => _.Key == "oidcsignout") && !sid.Equals(default(KeyValuePair<string, string[]>)))
            {
                //var sidClaim = ((ClaimsIdentity)HttpContext.Current.User.Identity).Claims.FirstOrDefault(_ => _.Type == Startup.SessionClaimType);
                //if (sidClaim != null && sidClaim.Value == sid.Value[0])
                {
                    try
                    {
                        var httpContext = context.Get<HttpContextBase>(typeof(HttpContextBase).FullName);
                        httpContext?.Session?.Clear();
                        httpContext?.Session?.Abandon();
                    }
                    catch (Exception ex)
                    {
                        logger.WriteError("Session cleanup error", ex);
                    }

                    context.Authentication.SignOut($"{CookieAuthenticationDefaults.AuthenticationType}");
                    //context.Authentication.SignOut(
                    //    context.Authentication.GetAuthenticationTypes()
                    //        .Select(o => o.AuthenticationType).ToArray());
                    context.Response.Cookies.Delete($"{CookieAuthenticationDefaults.CookiePrefix}{CookieAuthenticationDefaults.AuthenticationType}", new CookieOptions()
                    {
                        Path =
                            $"/{new Uri(OpenIdConnectAuthentication.Default.RedirectUri).GetComponents(UriComponents.Path, UriFormat.Unescaped)}"
                    });

                    await context.Response.WriteAsync("<!DOCTYPE html><html><body>loggedout</body></html>");
                    //Task.FromResult(0);
                    return;
                }
            }

            await Next.Invoke(context);
            //Console.WriteLine("End Request");
        }
    }
}
