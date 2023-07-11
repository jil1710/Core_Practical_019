using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Practical_19.Interfaces;
using Practical_19.Models;
using Practical_19.Repository;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(connectionString));


builder.Services.AddScoped<IAuthentication, AuthenticationRepository>();
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>();
builder.Services.ConfigureApplicationCookie(config =>
{

    config.LoginPath = "/Auth/Login";
});

builder.Services.AddSession();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.AccessDeniedPath = new PathString("/Administration/AccessDenied");
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!))
    };
    
});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseSession();
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
//Add JWToken to all incoming HTTP Request Header
app.Use(async (context, next) =>
{
    var JWToken = context.Session.GetString("JWToken");
    if (!string.IsNullOrEmpty(JWToken))
    {
        context.Request.Headers.Add("Authorization", "Bearer " + JWToken);
    }
    await next();
});
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();


public class AuthorizeAttribute : TypeFilterAttribute
{
    public AuthorizeAttribute(params string[] claim) : base(typeof(AuthorizeFilter))
    {
        Arguments = new object[] { claim };
    }
}

public class AuthorizeFilter : IAuthorizationFilter
{
    readonly string[] _claim;

    public AuthorizeFilter(params string[] claim)
    {
        _claim = claim;
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var IsAuthenticated = context.HttpContext.User.Identity.IsAuthenticated;
        var claimsIndentity = context.HttpContext.User.Identity as ClaimsIdentity;

        if (IsAuthenticated)
        {
            bool flagClaim = false;
            foreach (var item in _claim)
            {
                if (context.HttpContext.User.HasClaim(ClaimTypes.Role, item))
                    flagClaim = true;
            }
            if (!flagClaim)
                context.Result = new RedirectResult("~/Administration/AccessDenied");
        }
        else
        {
            context.Result = new RedirectResult("~/Auth/Login");
        }
        return;
    }
}
