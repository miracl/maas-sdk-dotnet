using IdentityModel;
using Miracl;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace WebApplication4.Controllers
{
    public class SigninMiraclController : Controller
    {
        public async Task<ActionResult> Index()
        {
            ViewBag.Code = Request.QueryString["code"] ?? "none";

            var state = Request.QueryString["state"];
            
            ViewBag.State = state;

            ViewBag.Error = Request.QueryString["error"] ?? "none";

            return View();
        }

        [HttpPost]
        [ActionName("Index")]
        public async Task<ActionResult> GetToken()
        {            
            IdentityModel.Client.TokenResponse response = await HomeController.Client.ValidateAuthorization(Request.QueryString);
            if (response != null)
            {
                var identity = await HomeController.Client.GetIdentity(response);
                Request.GetOwinContext().Authentication.SignIn(identity);
            }

            if (!string.IsNullOrEmpty(response.IdentityToken))
            {
                ViewBag.IdentityTokenParsed = ParseJwt(response.IdentityToken);
            }
            if (!string.IsNullOrEmpty(response.AccessToken))
            {
                ViewBag.AccessTokenParsed = ParseJwt(response.AccessToken);
            }

            return View("Token", response);
        }
        
        private string ParseJwt(string token)
        {
            if (!token.Contains("."))
            {
                return token;
            }

            var parts = token.Split('.');
            var part = Encoding.UTF8.GetString(Base64Url.Decode(parts[1]));

            var jwt = JObject.Parse(part);
            return jwt.ToString();
        }
    }
}