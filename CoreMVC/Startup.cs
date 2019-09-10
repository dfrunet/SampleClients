using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CoreMVC.AutomaticTokenManagement;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace CoreMVC
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            //services.Configure<CookiePolicyOptions>(options =>
            //{
            //    // This lambda determines whether user consent for non-essential cookies is needed for a given request.
            //    options.CheckConsentNeeded = context => true;
            //    options.MinimumSameSitePolicy = SameSiteMode.None;
            //});

            //services.AddAuthentication("asp-net-core-mvc-sample-cookie")
            //    .AddCookie("asp-net-core-mvc-sample-cookie", _ => { _.ForwardChallenge = "AzureAD"; })
            services.AddAuthentication(options =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = "oidc";
                })
                .AddCookie(options =>
                {
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                    options.Cookie.Name = "mvchybridautorefresh";
                })
                .AddAutomaticTokenManagement()


                //services.AddAuthentication(AzureADDefaults.AuthenticationScheme)
                //    .AddAzureAD(_ =>
                //    {
                //        _.ClientId = "ff6ff51e-4d7d-4349-9522-d7f90fd995be";
                //        _.TenantId = "common";
                //        _.ClientSecret = "Le7su+F*6z1?chJu5F*-Wb@e*GBQFM:r";
                //        _.Instance = "https://login.microsoftonline.com/";

                //        //"Domain": "[Enter the domain of your tenant, e.g. contoso.onmicrosoft.com]",
                //        //"TenantId": "[Enter 'common', or 'organizations' or the Tenant Id (Obtained from the Azure portal. Select 'Endpoints' from the 'App registrations' blade and use the GUID in any of the URLs), e.g. da41245a5-11b3-996c-00a8-4d99re19f292]",
                //        //"ClientId": "[Enter the Client Id (Application ID obtained from the Azure portal), e.g. ba74781c2-53c2-442a-97c2-3d60re42f403]",
                //        _.CallbackPath = "/signin-oidc";

                //    })
                //    .AddOpenIdConnect("aad", "Azure AD", options =>
                //    {
                //        options.SignInScheme = "ext";
                //        options.SignOutScheme = "signout";

                //        options.Authority = "https://login.windows.net";
                //        options.ClientId = "ff6ff51e-4d7d-4349-9522-d7f90fd995be";
                //        options.ResponseType = "id_token";
                //        options.CallbackPath = "/signin-aad";
                //        options.SignedOutCallbackPath = "/signout-callback-aad";
                //        options.RemoteSignOutPath = "/signout-aad";
                //        options.TokenValidationParameters = new TokenValidationParameters
                //        {
                //            NameClaimType = "name",
                //            RoleClaimType = "role"
                //        };
                //        options.UseTokenLifetime = true;
                //    })
                //    .AddMicrosoftAccount(options =>
                //    //{
                //    //    options.ClientId = Configuration["Authentication:Microsoft:ClientId"];
                //    //    options.ClientSecret = Configuration["Authentication:Microsoft:ClientSecret"];
                //    //}); 
                //    //.AddMicrosoftAccount(options =>
                //    {
                //        //options.SignInScheme = "external";//IdentityServerConstants.ExternalCookieAuthenticationScheme;
                //        options.ClientId = "ff6ff51e-4d7d-4349-9522-d7f90fd995be";//Configuration["Authentication:Microsoft:ClientId"];
                //        options.ClientSecret =
                //            "Le7su+F*6z1?chJu5F*-Wb@e*GBQFM:r"; 
                //        //options.ClaimActions
                //    });


                .AddOpenIdConnect("oidc", options =>
                {
                    options.Authority = "https://demo.identityserver.io/";
                    //options.ClientId = "server.hybrid";

                    options.ClientId = "server.hybrid.short";
                    //openid profile email api offline_access
                    options.ClientSecret = "secret";
                    //options.Events = new OpenIdConnectEvents
                    //{
                    //    //OnTicketReceived = ctx =>
                    //    //{
                    //    //    ctx.ReturnUri = "http://ya.ru";
                    //    //    return Task.CompletedTask;
                    //    //},
                    //    OnAuthorizationCodeReceived = ctx =>
                    //    {
                    //        ctx.TokenEndpointRequest.RedirectUri = "";
                    //        ctx.TokenEndpointResponse.RequestUri = "";
                    //        ctx.TokenEndpointResponse.TargetLinkUri = "";
                    //        return Task.CompletedTask;
                    //    },
                    //    OnTokenValidated = ctx => { return Task.CompletedTask; }
                    //};

                    options.ResponseType = "code id_token";
                    //options.CallbackPath = "/signin-oidc";
                    options.Scope.Clear();
                    options.Scope.Add("openid");
                    options.Scope.Add("profile");
                    options.Scope.Add("email");
                    options.Scope.Add("api");
                    options.Scope.Add("offline_access");

                    options.ClaimActions.MapAllExcept("iss", "nbf", "exp", "aud", "nonce", "iat", "c_hash");

                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.SaveTokens = true;

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = JwtClaimTypes.Name,
                        RoleClaimType = JwtClaimTypes.Role,
                    };
                });


            //services.Configure<OpenIdConnectOptions>(AzureADDefaults.OpenIdScheme, options =>
            //{
            //    options.Authority = options.Authority + "/v2.0/";         // Microsoft identity platform
            //    options.Scope.Add("email");
            //    options.TokenValidationParameters.ValidateIssuer = false; // accept several tenants (here simplified)
            //});

            services.AddMvc(_ =>
                {
                    var policy = new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser()
                        .Build();
                    _.Filters.Add(new AuthorizeFilter(policy));
                }
            ).SetCompatibilityVersion(CompatibilityVersion.Version_2_2);



            services.AddHttpClient();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");

            });
        }
    }
}
