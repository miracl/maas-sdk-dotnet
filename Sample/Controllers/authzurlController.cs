using SampleWebApp.Controllers;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace SampleWebApp.Controllers
{
    public class authzurlController : Controller
    {
        [HttpPost]
        public async Task<ActionResult> Index()
        {
            string url = Request.Url.ToString().Replace(Request.Url.Segments[Request.Url.Segments.Length - 1], "");
            return Json(new { authorizeURL = await HomeController.GetUrl(url) });
        }
    }
}