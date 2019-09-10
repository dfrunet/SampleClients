using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace CoreMVC.Controllers
{
    public class TestController : Controller
    {

        public TokenClient TokenClient { get; }

        public TestController(TokenClient tokenClient) => TokenClient = tokenClient;

        // GET
        public async Task<HttpResponseMessage> Index()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "https://demo.identityserver.io/api/test");
            var accessToken = await TokenClient.GetToken();
            request.SetBearerToken(accessToken);
            var client = HttpClientFactory.Create();
            var response = await client.SendAsync(request, new CancellationToken());
            return response;
        }
    }
}