using IdentityManager;
using IdentityManager.Data;
using IdentityManager.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// Add services to the container.
var connectionString = config.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
	options.UseSqlServer(connectionString));

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = false)
	.AddRoles<IdentityRole>()
	.AddEntityFrameworkStores<ApplicationDbContext>()
	.AddDefaultUI();
//builder.Services.AddIdentity<IdentityUser, IdentityRole>(options => options.SignIn.RequireConfirmedAccount = false)
//	.AddEntityFrameworkStores<ApplicationDbContext>()
//	.AddDefaultTokenProviders()	// No need this when user AddDefaultIdentity
//	.AddDefaultUI(); //System will get Identity Razor pages as default not account controller
builder.Services.Configure<IdentityOptions>(options =>
{
	options.Password.RequiredLength = 5;
	options.Password.RequireLowercase = true;
	options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromSeconds(30);
	options.Lockout.MaxFailedAccessAttempts = 2;
});

//builder.Services.ConfigureApplicationCookie(options =>
//{
//	options.AccessDeniedPath = new Microsoft.AspNetCore.Http.PathString("/Account/AccessDenied");
//});

builder.Services.AddAuthentication().AddFacebook(options =>
{
	options.AppId = config.GetValue<string>("ExternalLogin:Facebook:AppId");
	options.AppSecret = config.GetValue<string>("ExternalLogin:Facebook:SecretKey");
});

builder.Services.AddAuthorization(opt =>
{
	opt.AddPolicy("Admin", pol => pol.RequireRole("Admin"));
	opt.AddPolicy("UserAndAdmin", pol => pol.RequireRole("Admin").RequireRole("User"));
	opt.AddPolicy("Admin_CreateAccess", pol => pol.RequireRole("Admin").RequireClaim("create", "True"));
	opt.AddPolicy("Admin_Create_Edit_DeleteAccess", pol => pol.RequireRole("Admin")
		.RequireClaim("create", "True")
		.RequireClaim("edit", "True")
		.RequireClaim("delete", "True"));
	opt.AddPolicy("Admin_Create_Edit_DeleteAccess_Or_SuperAdmin",
		pol => pol.RequireAssertion(
			context =>
			(
				context.User.IsInRole("Admin")
					&& context.User.HasClaim(c => c.Type == "Create" && c.Value == "True")
					&& context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True")
					&& context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
			) || context.User.IsInRole("SuperAdmin")
		));
});

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
	app.UseExceptionHandler("/Home/Error");
	// The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
	app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
	name: "default",
	pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

app.Run();


