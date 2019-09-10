using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using MVC.ViewModels;

namespace MVC.Controllers
{
    public class AccountController : Controller
    {
        //public AccountController()
        //{
        //}

        //
        // GET: /Account/Login
        public ActionResult AutoLogin()
        {
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View(new LoginViewModel());
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            FormsAuthentication.RedirectFromLoginPage(model.Login, model.RememberMe);
            return new EmptyResult();
        }

        public ActionResult LogOff()
        {
            FormsAuthentication.SignOut();
            //HttpContext.CurrentHandler
            return RedirectToAction("Index", "Home");
        }


    }
}