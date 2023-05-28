using IdentityManager.Models;
using IdentityManager.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore.Query.Internal;
using System.ComponentModel;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace IdentityManager.Controllers
{
	[Authorize]
	public class AccountController : Controller
	{
		private readonly UserManager<IdentityUser> _userManager;
		private readonly RoleManager<IdentityRole> _roleManager;
		private readonly SignInManager<IdentityUser> _signInManager;
		private readonly IEmailServiceCustom _emailServiceCustom;
		private readonly UrlEncoder _urlEncoder;
		public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
			IEmailServiceCustom emailServiceCustom, UrlEncoder urlEncoder, RoleManager<IdentityRole> roleManager)
		{
			_userManager = userManager;
			_signInManager = signInManager;
			_emailServiceCustom = emailServiceCustom;
			_urlEncoder = urlEncoder;
			_roleManager = roleManager;
		}
		public IActionResult Index()
		{
			return View();
		}

		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> Register(string returnUrl = null)
		{
			if(!await _roleManager.RoleExistsAsync("Admin"))
			{
				await _roleManager.CreateAsync(new IdentityRole("Admin"));
				await _roleManager.CreateAsync(new IdentityRole("User"));
			}

			//List<SelectListItem> roleListItems = new List<SelectListItem>()
			//{
			//	new SelectListItem
			//	{
			//		Value="Admin",
			//		Text = "Admin"
			//	},
			//	new SelectListItem
			//	{
			//		Value="User",
			//		Text = "User"
			//	}
			//};

			ViewData["ReturnUrl"] = returnUrl;
			RegisterViewModel model = new RegisterViewModel()
			{
				RoleList = await GetRoleList()
			};
			return View(model);
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		[AllowAnonymous]
		public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
		{
			ViewData["ReturnUrl"] = returnUrl;
			returnUrl = returnUrl ?? Url.Content("~/");
			if (ModelState.IsValid)
			{
				var user = new ApplicationUser { UserName = model.Email, Email = model.Email, Name = model.Name };
				var result = await _userManager.CreateAsync(user, model.Password);

				if (result.Succeeded)
				{
					if(model.RoleSelected!=null && model.RoleSelected.Length>0 && model.RoleSelected == "Admin")
					{
						await _userManager.AddToRoleAsync(user, "Admin");
					}
					else
					{
						await _userManager.AddToRoleAsync(user, "User");
					}

					var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
					var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);
					await _emailServiceCustom.SendEmailAsync(model.Email, "Confirm your account - Identity Manager",
						"Please confirm your account by clicking here : <a href=\"" + callbackUrl + "\">Account confirmation Link</a>");


					ViewBag.Header = "Registration Confirmation";
					ViewBag.Message = "Thank you for registration, Please check your email to confirm your account.";
					return View("Confirmation");
				}
				AddErrors(result);
			}
			model.RoleList = await GetRoleList();
			return View(model);
		}

		[HttpGet]
		[AllowAnonymous]
		public IActionResult Login(string returnUrl = null)
		{
			ViewData["ReturnUrl"] = returnUrl;

			return View();
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		[AllowAnonymous]
		public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
		{
			ViewData["ReturnUrl"] = returnUrl;
			returnUrl = returnUrl ?? Url.Content("~/");
			if (ModelState.IsValid)
			{
				var user = await _userManager.FindByNameAsync(model.Email);
				if (user != null && !user.EmailConfirmed)
				{
					ModelState.AddModelError(string.Empty, "Your account has not been confirmed yet.");
					return View(model);
				}

				var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);
				if (result.Succeeded)
				{
					return LocalRedirect(returnUrl);
				}
				if (result.RequiresTwoFactor)
				{
					return RedirectToAction(nameof(VerifyAuthenticatorCode), new { returnurl = returnUrl, RememberMe = model.RememberMe });
				}
				if (result.IsLockedOut)
				{
					//ViewBag.Header = "Locked out";
					//ViewBag.Message = "This account has been locked out, please try again later.";
					//return View("Error");

					ModelState.AddModelError(string.Empty, "This account has been locked out, please try again later.");
					return View(model);
				}
				else
				{
					ModelState.AddModelError(string.Empty, "Invalid login attempt");
					return View(model);
				}
			}
			return View(model);
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Logoff()
		{
			await _signInManager.SignOutAsync();
			return RedirectToAction(nameof(HomeController.Index), "Home");
		}

		[HttpGet]
		[AllowAnonymous]
		public IActionResult ForgotPassword()
		{
			return View();
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		[AllowAnonymous]
		public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
		{
			if (ModelState.IsValid)
			{
				var user = await _userManager.FindByEmailAsync(model.Email);
				if (user == null)
				{
					return RedirectToAction("ForgotPasswordConfirmation");
				}
				var code = await _userManager.GeneratePasswordResetTokenAsync(user);
				var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);
				await _emailServiceCustom.SendEmailAsync(model.Email, "Reset Password - Identity Manager",
					"Please reset your password by clicking here : <a href=\"" + callbackUrl + "\">Reset Password Link</a>");
				return RedirectToAction("ForgotPasswordConfirmation");
			}
			return RedirectToAction(nameof(HomeController.Index), "Home");
		}

		[HttpGet]
		[AllowAnonymous]
		public IActionResult ForgotPasswordConfirmation()
		{
			ViewBag.Header = "Forgot your password?";
			ViewBag.Message = "Please check your email to reset your password.";
			return View("Confirmation");
		}

		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> ResetPassword(string userId = null, string code = null)
		{
			ViewBag.Header = "Reset Password";
			ViewBag.Message = "Reset password failed, please contact with administrator.";

			if (userId == null || code == null)
			{
				return View("Error");
			}

			var user = await _userManager.FindByIdAsync(userId);
			ResetPasswordViewModel model = new ResetPasswordViewModel
			{
				Code = code,
				Email = user.Email
			};
			return View(model);
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		[AllowAnonymous]
		public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
		{
			if (ModelState.IsValid)
			{
				var user = await _userManager.FindByEmailAsync(model.Email);
				if (user == null)
				{
					return RedirectToAction("ResetPasswordConfirmation");
				}
				var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
				if (result.Succeeded)
				{
					return RedirectToAction("ResetPasswordConfirmation");
				}
				AddErrors(result);
			}
			return View(model);
		}

		[HttpGet]
		[AllowAnonymous]
		public IActionResult ResetPasswordConfirmation()
		{
			ViewBag.Header = "Reset password confirmation";
			var url = Url.Action("Login", "Account", new { }, protocol: HttpContext.Request.Scheme);
			ViewBag.Message = "Your password has been reset. <a href=\"" + url + "\">Click here to log in </a>.";
			return View("Confirmation");
		}

		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> ConfirmEmail(string userId = null, string code = null)
		{
			ViewBag.Header = "Confirm Email";
			ViewBag.Message = "Email confirmation failure, please contact with administrator.";
			if (userId == null)
			{
				return View("Error");
			}
			if (code == null)
			{
				return View("Error");
			}
			var user = await _userManager.FindByIdAsync(userId);
			if (user == null)
			{
				return View("Error");
			}
			var result = await _userManager.ConfirmEmailAsync(user, code);
			if (!result.Succeeded)
			{
				return View("Error");
			}
			ViewBag.Header = "Confirm Email";
			var url = Url.Action("Login", "Account", new { }, protocol: HttpContext.Request.Scheme);
			ViewBag.Message = "Thank you for confirming your email. <a href=\"" + url + "\">Click here to log in </a>.";
			return View("Confirmation");
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		[AllowAnonymous]
		public IActionResult ExternalLogin(string provider, string returnUrl)
		{
			//Request a redirect to the external login provider
			var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });
			var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
			return Challenge(properties, provider);
		}

		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
		{
			returnUrl = returnUrl ?? Url.Content("~/");
			if (remoteError != null)
			{
				ModelState.AddModelError(string.Empty, $"Error from external provider:{remoteError}");
				return View(nameof(Login));
			}
			var info = await _signInManager.GetExternalLoginInfoAsync();
			if (info == null)
			{
				return RedirectToAction(nameof(Login));
			}
			//Sign in the user with this external login provider, if the user already has a log in
			var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
			if (result.Succeeded)
			{
				//update any authentication token
				await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
				return LocalRedirect(returnUrl);
			}
			if (result.RequiresTwoFactor)
			{
				return RedirectToAction(nameof(VerifyAuthenticatorCode), new { returnUrl = returnUrl });
			}
			else
			{
				//if user does not have account, ask user to create one
				ViewData["ReturnUrl"] = returnUrl;
				ViewData["ProviderDisplayName"] = info.ProviderDisplayName;
				var email = info.Principal.FindFirstValue(ClaimTypes.Email);
				var name = info.Principal.FindFirstValue(ClaimTypes.Name);
				return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email, Name = name });
			}
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		[AllowAnonymous]
		public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl = null)
		{
			if (ModelState.IsValid)
			{
				var info = await _signInManager.GetExternalLoginInfoAsync();
				if (info == null)
				{
					return View("Error");
				}
				var user = new ApplicationUser { UserName = model.Email, Email = model.Email, Name = model.Name };
				var result = await _userManager.CreateAsync(user);
				if (result.Succeeded)
				{
					result = await _userManager.AddLoginAsync(user, info);
					if (result.Succeeded)
					{
						await _userManager.AddToRoleAsync(user, "User");

						await _signInManager.SignInAsync(user, isPersistent: false);
						await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
						return LocalRedirect(returnUrl);
					}
				}
				AddErrors(result);
			}
			ViewData["ReturnUrl"] = returnUrl;
			return View(model);
		}
		[HttpGet]
		public async Task<IActionResult> EnableAuthenticator()
		{
			string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

			var user = await _userManager.GetUserAsync(User);
			await _userManager.ResetAuthenticatorKeyAsync(user);
			var token = await _userManager.GetAuthenticatorKeyAsync(user);
			string AuthenticatorUri = string.Format(AuthenticatorUriFormat, _urlEncoder.Encode("IdentityManager"),
				_urlEncoder.Encode(user.Email), token);
			var model = new TwoFactorAuthenticationViewModel() { Token = token, QRCodeUrl = AuthenticatorUri };
			return View(model);
		}

		[HttpGet]
		public async Task<IActionResult> RemoveAuthenticator()
		{
			var user = await _userManager.GetUserAsync(User);
			await _userManager.ResetAuthenticatorKeyAsync(user);
			await _userManager.SetTwoFactorEnabledAsync(user, false);
			return RedirectToAction(nameof(Index), "Home");
		}
		[HttpPost]
		[AutoValidateAntiforgeryToken]
		public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel model)
		{
			if (ModelState.IsValid)
			{
				var user = await _userManager.GetUserAsync(User);
				var Succeeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
				if (Succeeded)
				{
					await _userManager.SetTwoFactorEnabledAsync(user, true);
				}
				else
				{
					ModelState.AddModelError("Verify", "Your two factor auth code could not be validated.");
					return View(model);
				}
			}
			return RedirectToAction(nameof(AuthenticationConfirmation));
		}

		public IActionResult AuthenticationConfirmation(TwoFactorAuthenticationViewModel model)
		{
			ViewBag.Header = "Two Factor Authentication Setup";
			ViewBag.Message = "Two Factor Authentication has been setup successfully.";
			return View("Confirmation");
		}

		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string returnUrl = null)
		{
			var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
			if (user == null)
			{
				return View("Error");
			}
			ViewData["ReturnUrl"] = returnUrl;
			return View(new VerifyAuthenticatorViewModel { ReturnUrl = returnUrl, RememberMe = rememberMe });
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		[AllowAnonymous]
		public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorViewModel model)
		{
			model.ReturnUrl = model.ReturnUrl ?? Url.Content("~/");
			if (!ModelState.IsValid)
			{
				return View(model);
			}
			var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe, rememberClient: true);
			if (result.Succeeded)
			{
				return LocalRedirect(model.ReturnUrl);
			}
			if (result.IsLockedOut)
			{
				ModelState.AddModelError(string.Empty, "This account has been locked out, please try again later.");
				return View(model);
			}
			else
			{
				ModelState.AddModelError(string.Empty, "Invalid Code");
				return View(model);
			}
		}

		[HttpGet]
		public IActionResult AccessDenied()
		{
			ViewBag.Header = "Access Denied";
			ViewBag.Message = "Sorry! You are not allow to access this page.";
			return View("Error");
		}

		private void AddErrors(IdentityResult result)
		{
			foreach (var error in result.Errors)
			{
				ModelState.AddModelError(string.Empty, error.Description);
			}
		}

		private async Task<List<SelectListItem>> GetRoleList()
		{
			List<SelectListItem> roleListItems = new List<SelectListItem>()
			{
				new SelectListItem
				{
					Value="Admin",
					Text = "Admin"
				},
				new SelectListItem
				{
					Value="User",
					Text = "User"
				}
			};
			return roleListItems;
		}
	}
}
