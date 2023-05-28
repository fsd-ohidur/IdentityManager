using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityManager.Models
{
	public class ApplicationUser : IdentityUser
	{
		[Required]
		public string Name { get; set; }
		[NotMapped]
		public string RoleId { get; set; }
		[NotMapped]
		[ValidateNever]
		public string Role { get; set; }
		[NotMapped]
		[ValidateNever]
		public IEnumerable<SelectListItem> RoleList { get; set; }

	}
}
