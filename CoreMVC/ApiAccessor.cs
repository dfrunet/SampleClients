using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreMVC
{

    public class TokenClientOptions
    {
        public string Address { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
    }

    public class TokenClient 
    {
        private const string AccessTokenCacheKey = "access_token";

        public HttpClient Client { get; }
        public TokenClientOptions Options { get; }
        public ILogger<TokenClient> Logger { get; }
        public IDistributedCache Cache { get; }


        public TokenClient(HttpClient client, IOptions<TokenClientOptions> options,
            IDistributedCache cache,
            ILogger<TokenClient> logger)
        {
            Client = client;
            Options = options.Value;
            Cache = cache;
            Logger = logger;
        }
        

        public async Task<string> GetToken()
        {
            var token = Cache.GetString(AccessTokenCacheKey);
            if (token != null)
                return token;

            var response = await Client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = Options.Address,
                ClientId = Options.ClientId,
                ClientSecret = Options.ClientSecret
            });

            Cache.SetString(AccessTokenCacheKey, response.AccessToken,
                new DistributedCacheEntryOptions()
                    {AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(response.ExpiresIn)});
            return response.AccessToken;
        }


    }

    public static class Extensions
    {
        public static void AddTokenClient(this IServiceCollection services) {
            services.Configure<TokenClientOptions>(options =>
            {
                options.Address = "https://login.dev.apptoyou.com/connect/token";
                options.Address = "https://demo.identityserver.io/connect/token";
                options.ClientId = "client";//"client";
                options.ClientSecret = "secret";//"aditrohr-rules-2017";
            });

            services.AddDistributedMemoryCache();
            services.AddHttpClient<TokenClient>();
        }
    }


    public class ApiAccessor
    {
        public TokenClient TokenClient { get; }

        public ApiAccessor(TokenClient tokenClient)
        {
            TokenClient = tokenClient;
        }

        public async Task<HttpResponseMessage> CallApiAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var accessToken = await TokenClient.GetToken();
            request.SetBearerToken(accessToken);
            var client = HttpClientFactory.Create();
            return await client.SendAsync(request, cancellationToken);
        }

    }



}
