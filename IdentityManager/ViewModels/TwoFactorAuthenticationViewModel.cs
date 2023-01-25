using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager.ViewModels
{
    public class TwoFactorAuthenticationViewModel
    {
        // used to login
        public string Code { get; set; }

        // used to register/ signup
        public string Token { get; set; }
    }
}
