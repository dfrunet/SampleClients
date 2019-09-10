using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace CoreMVC.Controllers
{
    public class AccountController : Controller
    {
        // GET
        public IActionResult Login(string returnUrl)
        {
            string provider = "Microsoft";
            //string returnUrl2 = Url.Action("ExternalLoginCallback", new { returnUrl = returnUrl });

            //// start challenge and roundtrip the return URL
            //var props = new AuthenticationProperties
            //{
            //    RedirectUri = returnUrl2,
            //    Items = { { "scheme", provider } }
            //};

            return new ChallengeResult(provider);
        }
    }
}