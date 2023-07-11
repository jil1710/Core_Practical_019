using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Practical_19.Controllers
{
    [Authorize("User")]
    public class UserController : Controller
    {
        public IActionResult Dashboard()
        {
            return View();
        }
    }
}
