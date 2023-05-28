using IdentityManager.Data;
using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityManager.Controllers
{
	public class UserController : Controller
	{
		private readonly ApplicationDbContext _context;
		private readonly UserManager<IdentityUser> _userManager;

		public UserController(ApplicationDbContext context, UserManager<IdentityUser> userManager)
		{
			_context = context;
			_userManager = userManager;
		}
		public IActionResult Index()
		{
			var userList = _context.ApplicationUsers.ToList();
			var userRole = _context.UserRoles.ToList();
			var roles = _context.Roles.ToList();

			foreach (var user in userList)
			{
				var role = userRole.FirstOrDefault(u => u.UserId == user.Id);
				if (role == null)
				{
					user.Role = "None";
				}
				else
				{
					user.Role = roles.FirstOrDefault(u => u.Id == role.RoleId).Name;
				}
			}
			return View(userList);
		}
		public IActionResult Edit(string userId)
		{
			var model = _context.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
			if (model == null)
			{
				return NotFound();
			}

			var userRole = _context.UserRoles.ToList();
			var roles = _context.Roles.ToList();
			var role = userRole.FirstOrDefault(u => u.UserId == model.Id);
			if (role != null)
			{
				model.RoleId = roles.FirstOrDefault(u => u.Id == role.RoleId).Id;
			}
			model.RoleList = _context.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
			{
				Text = u.Name,
				Value = u.Id
			});
			return View(model);
		}
		[HttpPost]
		[AutoValidateAntiforgeryToken]
		public async Task<IActionResult> Edit(ApplicationUser model)
		{
			if (ModelState.IsValid)
			{
				var obj = _context.ApplicationUsers.FirstOrDefault(u => u.Id == model.Id);
				if (obj == null)
				{
					return NotFound();
				}

				var userRole = _context.UserRoles.FirstOrDefault(u => u.UserId == obj.Id);
				if (userRole != null)
				{
					var oldRole = _context.Roles.Where(u => u.Id == userRole.RoleId).Select(e => e.Name).FirstOrDefault();
					//Remove Old Role
					await _userManager.RemoveFromRoleAsync(obj, oldRole);
				}
				//Assign New Role
				await _userManager.AddToRoleAsync(obj, _context.Roles.FirstOrDefault(u => u.Id == model.RoleId).Name);
				obj.Name = model.Name;
				_context.SaveChanges();
				TempData[SD.Success] = "User has been edited successfully";

				return RedirectToAction(nameof(Index));
			}
			model.RoleList = _context.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
			{
				Text = u.Name,
				Value = u.Id
			});
			return View(model);
		}


		//[HttpPost]
		//[AutoValidateAntiforgeryToken]
		//public async Task<IActionResult> Delete(string userId)
		//{
		//	var obj = _context.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
		//	if (obj == null)
		//	{
		//		TempData[SD.Error] = "Sorry! User does not exist to delete.";
		//		return RedirectToAction(nameof(Index));
		//	}

		//	var userRole = _context.UserRoles.FirstOrDefault(u => u.UserId == obj.Id);
		//	if (userRole != null)
		//	{
		//		var oldRole = _context.Roles.Where(u => u.Id == userRole.RoleId).Select(e => e.Name).FirstOrDefault();
		//		//Remove Old Role
		//		await _userManager.RemoveFromRoleAsync(obj, oldRole);
		//	}
		//	TempData[SD.Success] = "User's role has been deleted successfully";

		//	return RedirectToAction(nameof(Index));
		//}

		[HttpPost]
		[AutoValidateAntiforgeryToken]
		public async Task<IActionResult> LockUnlock(string userId)
		{
			var obj = _context.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
			if (obj == null)
			{
				TempData[SD.Error] = "Sorry! User does not exist to delete.";
				return RedirectToAction(nameof(Index));
			}

			if(obj.LockoutEnd!=null && obj.LockoutEnd > DateTime.Now)
			{
				//User locked and should Lockout
				obj.LockoutEnd=DateTime.Now;
				TempData[SD.Success] = "User unlocked successfully";
			}
			else
			{
				obj.LockoutEnd = DateTime.Now.AddYears(100);
				TempData[SD.Success] = "User locked successfully";
			}
			_context.SaveChanges();

			return RedirectToAction(nameof(Index));
		}

		[HttpPost]
		[AutoValidateAntiforgeryToken]
		public async Task<IActionResult> Delete(string userId)
		{
			var obj = _context.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
			if (obj == null)
			{
				TempData[SD.Error] = "Sorry! User does not exist to delete.";
				return RedirectToAction(nameof(Index));
			}

			_context.ApplicationUsers.Remove(obj);
			_context.SaveChanges();
			TempData[SD.Success] = "User deleted successfully";

			return RedirectToAction(nameof(Index));
		}
	}
}
