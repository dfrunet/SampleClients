using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Helpers;
using IdentityServer3.AccessTokenValidation;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Owin;

[assembly: OwinStartup(typeof(MVCBearerNuget.Startup))]
namespace MVCBearerNuget
{

    public class Startup
    {

        private ILogger logger;


        public void Configuration(IAppBuilder app)
        {
            app.UseIdentityServerBearerTokenAuthentication(new IdentityServerBearerTokenAuthenticationOptions
            {
                Authority = "https://demo.identityserver.io/",
                RequiredScopes = new[] { "api" }
            });

        }
    }
}