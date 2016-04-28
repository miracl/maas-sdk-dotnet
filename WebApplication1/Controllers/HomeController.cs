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
            ClientId = "tkcrgjxg2epqo",
            ClientSecret = "5BbIxnqsEoufNp6g4uCXRDwQt61icF1O7IDXObwR8PU",
            AuthenticationType = "Cookies"
        });

        public ActionResult Index()
        {
            var url = Client.GetAuthorizationRequestUrl("http://test.my");
            ViewBag.AuthorizationUri = url;
            return View();
        }

        [HttpPost]
        public ActionResult Index(string Logout)
        {
            if (Logout != null)
            {
                Client.ClearUserInfo(false);
                Request.GetOwinContext().Authentication.SignOut();
            }

            return RedirectToAction("Index");
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";
            return View();
        }
    }
}


