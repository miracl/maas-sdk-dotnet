using Miracl;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using System.Web.UI;

namespace WebApplication4.Controllers
{

    public class HomeController : Controller
    {
        internal static MiraclClient Client;

        public async Task<ActionResult> Index()
        {
            if (Client == null)
            {
                Client = new MiraclClient(new MiraclAuthenticationOptions
                 {
                     ClientId = "tkcrgjxg2epqo", //"4zfymvdt63cqi ",//
                     ClientSecret = "5BbIxnqsEoufNp6g4uCXRDwQt61icF1O7IDXObwR8PU", //"kvqw_uvQYHsa_P9-x3DL-NqmfQDAM1lFSN85jbqLmd8", //
                     AuthenticationType = "Cookies"
                 });
            }

            var url = await Client.GetAuthorizationRequestUrlAsync("http://test.my");
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


