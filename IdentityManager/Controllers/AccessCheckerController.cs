using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
	[Authorize]
	public class AccessCheckerController : Controller
	{
		[AllowAnonymous]
		//Everybody may access this
		public IActionResult AllAccess()
		{
			return View();
		}

		[Authorize]
		//Only logged in user access this
		public IActionResult AuthorizedAccess()
		{
			return View();
		}

		[Authorize(Roles = "User")]
		//Only user access this whose have role is user
		public IActionResult UserAccess()
		{
			return View();
		}

		[Authorize(Roles = "User,Admin")]
		//Only user access this whose have role is admin
		public IActionResult UserOrAdminAccess()
		{
			return View();
		}

		[Authorize(Policy =  "UserAndAdmin")]
		//Only user access this whose have role is admin
		public IActionResult UserAndAdminAccess()
		{
			return View();
		}

		[Authorize(Policy = "Admin")]
		//Only user access this whose have role is admin
		public IActionResult AdminAccess()
		{
			return View();
		}

		[Authorize(Policy = "Admin_CreateAccess")]

		//Only user access this whose have role is admin and have "Create" claims
		public IActionResult Admin_CreateAccess()
		{
			return View();
		}
		[Authorize(Policy = "Admin_Create_Edit_DeleteAccess")]

		//Only user access this whose have role is admin and have "Create/Edit/Delete" claims
		public IActionResult Admin_Create_Edit_DeleteAccess()
		{
			return View();
		}
		[Authorize(Policy = "Admin_Create_Edit_DeleteAccess_Or_SuperAdmin")]

		//Only user access this whose have role is admin and have "Create/Edit/Delete" claims (And Not or) or user is super admin
		public IActionResult Admin_Create_Edit_DeleteAccess_Or_SuperAdmin()
		{
			return View();
		}
	}
}
