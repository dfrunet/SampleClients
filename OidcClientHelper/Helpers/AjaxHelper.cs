using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;

namespace OidcClientHelper.Helpers
{
    static class AjaxHelper
    {

        public static bool IsAjaxRequest(this IOwinRequest request)
        {
            //Unified with Logon.Utilities
            // Angular defaults
            if (request.Accept?.Contains("application/json") ?? false)
            {
                return true;
            }
            // jQuery defaults
            if (string.Equals(request.Headers["X-Requested-With"], "XMLHttpRequest", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return false;
        }
    }
}
