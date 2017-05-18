using Newtonsoft.Json.Linq;
using SampleWebApp.Controllers;
using System.Net;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace SampleWebApp.Controllers
{
    public class authtokenController : Controller
    {
        [HttpPost]
        public async Task<ActionResult> Index()
        {
            string data = new System.IO.StreamReader(Request.InputStream).ReadToEnd();
            JToken code, userId;
            try
            {
                var d = JObject.Parse(data);
                if (!d.TryGetValue("code", out code) || !d.TryGetValue("userID", out userId))
                {
                    return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
                }
            }
            catch
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }

            var token = await HomeController.Client.ValidateAuthorizationCode(code.ToString(), userId.ToString());
            if (token == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.Unauthorized);
            }
            if (token.HttpErrorStatusCode != 0)
            {
                return new HttpStatusCodeResult(token.HttpErrorStatusCode);
            }
            
            return Json(token);
        }
    }
}