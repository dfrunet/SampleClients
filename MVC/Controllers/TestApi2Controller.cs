using System;
using System.Collections.Generic;
using System.Web.Http;

namespace MVC.Controllers
{
    public class TestApi2Controller : ApiController
    {
        // GET: api/TestApi2
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }
    }
}
