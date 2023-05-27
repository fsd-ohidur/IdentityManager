using IdentityManager.Data;
using IdentityManager.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// Add services to the container.
var connectionString = config.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
	options.UseSqlServer(connectionString));
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
	.AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();
builder.Services.Configure<IdentityOptions>(options =>
{
	options.Password.RequiredLength = 5;
	options.Password.RequireLowercase = true;
	options.Lockout.DefaultLockoutTimeSpan= TimeSpan.FromSeconds(30);
	options.Lockout.MaxFailedAccessAttempts= 2;
});

builder.Services.AddTransient<IEmailServiceCustom, EmailServiceCustom>();


builder.Services.AddAuthentication().AddFacebook(options =>
{
	options.AppId = config.GetValue<string>("ExternalLogin:Facebook:AppId");
	options.AppSecret = config.GetValue<string>("ExternalLogin:Facebook:SecretKey");
});

builder.Services.AddControllersWithViews();

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

app.Run();
