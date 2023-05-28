using IdentityManager.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Formats.Asn1;

namespace IdentityManager.Controllers
{
	public class RolesController : Controller
	{
		private readonly ApplicationDbContext _context;
		private readonly UserManager<IdentityUser> _userManager;
		private readonly RoleManager<IdentityRole> _roleManager;
		public RolesController(ApplicationDbContext context, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
		{
			_context = context;
			_userManager = userManager;
			_roleManager = roleManager;
		}

		public async Task<IActionResult> Index()
		{
			var roles = await _context.Roles.ToListAsync();
			return View(roles);
		}

		[HttpGet]
		public async Task<IActionResult> Upsert(string id)
		{
			if (string.IsNullOrEmpty(id))
			{
				//Create
				return View();
			}
			else
			{
				//Update
				var model = await _context.Roles.FirstOrDefaultAsync(u => u.Id == id);
				return View(model);
			}
		}

		[HttpPost]
		[AutoValidateAntiforgeryToken]
		public async Task<IActionResult> Upsert(IdentityRole model)
		{
			if (await _roleManager.RoleExistsAsync(model.Name))
			{
				//Error
				TempData[SD.Error] = "Role already exists.";
				return View(model);
			}
			if (string.IsNullOrEmpty(model.Id))
			{
				//Create
				model.Id = Guid.NewGuid().ToString();
				await _roleManager.CreateAsync(new IdentityRole { Id = model.Id, Name = model.Name });
				TempData[SD.Success] = "Role created successfully.";
			}
			else
			{
				//Update
				var roleExist = _context.Roles.FirstOrDefault(u => u.Id == model.Id);
				if (roleExist == null)
				{
					TempData[SD.Error] = "Role not found.";
					return RedirectToAction(nameof(Index));

				}
				roleExist.Name = model.Name;
				roleExist.NormalizedName = model.Name.ToUpper();
				var result = await _roleManager.UpdateAsync(roleExist);
				TempData[SD.Success] = "Role updated successfully.";

			}
			return RedirectToAction(nameof(Index));
		}


		[HttpPost]
		[AutoValidateAntiforgeryToken]
		public async Task<IActionResult> Delete(string id)
		{
			var roleExist = _context.Roles.FirstOrDefault(u=>u.Id==id);
			if (roleExist==null)
			{
				TempData[SD.Error] = "Sorry! Role does not exist to delete.";
				return RedirectToAction(nameof(Index));
			}

			var roleAssigned = _context.UserRoles.Where(u => u.RoleId == id).Count();
			if(roleAssigned> 0)
			{
				TempData[SD.Error] = "Sorry! Role already assigned to the user.";
				return RedirectToAction(nameof(Index));
			}
			await _roleManager.DeleteAsync(roleExist);
			TempData[SD.Success] = "Role deleted successfully.";

			return RedirectToAction(nameof(Index));
		}
	}
}
