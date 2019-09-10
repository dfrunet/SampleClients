using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace MVC.Controllers
{
    public class HomeController : Controller
    {
        [AllowAnonymous]
        public ActionResult Index()
        {
            return View();
        }


        [AllowAnonymous]
        [ChildActionOnly]
        public ActionResult Configuration(string request)
        {
            var psth = new Uri(request).GetComponents(UriComponents.Path, UriFormat.UriEscaped);
            IHtmlString output = new HtmlString("{q=\"w\"}"); 
            return PartialView(output);
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}