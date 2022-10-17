using IdentityManager.Models;
using IdentityManager.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityManager.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signManager;
        private readonly IEmailSender _emailSender;
        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _signManager = signInManager;
            _emailSender = emailSender;

        }


        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]

        public async Task<IActionResult> Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            RegisterViewModel registerVM = new RegisterViewModel();

            return View(registerVM);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel registerVM, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl = returnUrl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = registerVM.Email,
                    Email = registerVM.Email,
                    Name = registerVM.Name
                };

                var result = await _userManager.CreateAsync(user, registerVM.Password);
                if (result.Succeeded)
                {
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                    var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);


                    await _emailSender.SendEmailAsync(registerVM.Email, "Confirm Your Account - Identity Manager",
                        "Please confirm your account by clicking here : <a href=\"" + callbackUrl + "\">link</a>");

                    await _signManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnUrl);
                }
                AddErrors(result);
            }

            return View(registerVM);
        }


        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOff()
        {
            await _signManager.SignOutAsync();

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }



        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            return View();
        }




        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel loginVM, string returnUrl = null)

        {
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl = returnUrl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var result = await _signManager.PasswordSignInAsync(loginVM.Email, loginVM.Password, loginVM.RememberMe, lockoutOnFailure: true);

                if (result.Succeeded)
                {
                    return LocalRedirect(returnUrl);
                }
                else if (result.IsLockedOut)
                {
                    return View("Lockout");
                }

                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid attempt for login detected!");
                    return View(loginVM);
                }
            }

            return View(loginVM);
        }



        [HttpGet]
        public IActionResult ForgotPassword()
        {


            return View();
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassWord(ForgotPasswordViewModel forgotVM)

        {

            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(forgotVM.Email);
                if (user == null)
                {
                    return RedirectToAction("ForgotPasswordConfirmation");
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);


                await _emailSender.SendEmailAsync(forgotVM.Email, "Reset Password - Identity Manager",
                    "Please reset your password by clicking here : <a href=\"" + callbackUrl + "\">link</a>");


                return RedirectToAction("ForgotPasswordConfirmation");
            }


            return View(forgotVM);
        }



        [HttpGet]
        public IActionResult ForgotPasswordConfirmation()
        {

            return View();
        }


        [HttpGet]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassWord(ResetPasswordViewModel resetVM)

        {

            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(resetVM.Email);
                if (user == null)
                {
                    return RedirectToAction("ResetPasswordConfirmation");
                }

                var result = await _userManager.ResetPasswordAsync(user, resetVM.Code, resetVM.Password);

                if (result.Succeeded)
                {
                    return RedirectToAction("ResetPasswordConfirmation");
                }
                AddErrors(result);

            }


            return View();
        }


        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {

            return View();
        }



        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return View("Error");
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");

        }

        [HttpPost]
        [ValidateAntiForgeryToken]
         public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });
            var properties = _signManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

            return Challenge(properties, provider);
        }





        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {

            if(remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider:{remoteError}");
                return View(nameof(Login));
            }

            var info = _signManager.GetExternalLoginInfoAsync();

            if(info == null)
            {
                return RedirectToAction(nameof(Login));
            }

            var result = await _signManager.ExternalLoginSignInAsync(info.Result.LoginProvider, info.Result.ProviderKey, isPersistent: false);

            if (result.Succeeded)
            {
                await _signManager.UpdateExternalAuthenticationTokensAsync(await info);
                return LocalRedirect(returnUrl);
            }
            else
            {
                ViewData["ReturnUrl"] = returnUrl;
                ViewData["ProviderDisplayName"] = info.Result.ProviderDisplayName;
                var email = info.Result.Principal.FindFirstValue(ClaimTypes.Email);
                return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email });

            }

            
         
        }

    }
}
