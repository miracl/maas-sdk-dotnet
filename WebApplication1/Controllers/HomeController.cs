using Miracl;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using System.Web.UI;

namespace WebApplication4.Controllers
{

    public class HomeController : Controller
    {
        internal static MiraclClient Client = new MiraclClient(new MiraclAuthenticationOptions
        {
            ClientId = "CLIENT_ID",
            ClientSecret = "CLIENT_SECRET",
            AuthenticationType = "Cookies"
        });

        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Index(string Login, string Logout)
        {
            if (Login != null)
            {
                var url = Client.GetAuthorizationRequestUrl("https://test.my");
                return Redirect(url);
            }

            if (Logout != null)
            {
                Request.GetOwinContext().Authentication.SignOut();
            }


            return View();
        }

        public ActionResult SignIn()
        {
            var url = Client.GetAuthorizationRequestUrl("https://test.my");
            return Redirect(url);
        }

        public ActionResult SignOut()
        {
            Client.ClearUserInfo(true);
            Request.GetOwinContext().Authentication.SignOut();
            return Redirect("/");
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";
            return View();
        }
    }
}


