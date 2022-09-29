using IdentityManager.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager.Controllers
{
    public class AccountController:Controller
    {
        public AccountController()
        {

        }


        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]

        public async Task<IActionResult> Register()
        {
            RegisterViewModel registerVM = new RegisterViewModel();

            return View(registerVM);
        }
    }
}
