using System;
using System.Collections.Generic;
using System.Web.Http;

namespace MVC.Controllers
{
    [Authorize]
    public class TestApiController : ApiController
    {
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }
    }
}