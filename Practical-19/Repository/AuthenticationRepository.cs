using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Practical_19.Interfaces;
using Practical_19.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Practical_19.Repository
{
    public class AuthenticationRepository : IAuthentication
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticationRepository(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,RoleManager<IdentityRole> roleManager,IConfiguration configuration)
        {

            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
            this._configuration = configuration;
        }

        [NonAction]
        private async Task<string?> GenerateToken(IdentityUser user)
        {
            var skey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var cred = new SigningCredentials(skey, SecurityAlgorithms.HmacSha256);
            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Email,user.Email)

            };

            foreach (var role in await userManager.GetRolesAsync(user)) 
            {
                new Claim(ClaimTypes.Role,role);
            }

            var token = new JwtSecurityToken(_configuration["Jwt:Issuer"], _configuration["Jwt:Audience"], claims, expires: DateTime.Now.AddMinutes(15), signingCredentials: cred);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        public async Task<IdentityResult> RegisterAsync(RegisterViewModel model)
        {
            var user = new IdentityUser
            {
                UserName = model.Email,
                Email = model.Email
            };

            var role = new IdentityRole
            {
                Name = "User" // Change to User to check User Feature
            };

            var res = await roleManager.CreateAsync(role);

            var result = await userManager.CreateAsync(user, model.Password);
            await userManager.AddToRoleAsync(user, role.Name);
            return result;

        }

        public async Task<string> LoginAsync(LoginViewModel model)
        {
            var user = await userManager.FindByEmailAsync(model.Email);
            if (user != null)
            {
                var identityResult = await signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);
                if (identityResult.Succeeded)
                {
                    var token = await GenerateToken(user);
                    return token!;
                }
                return null;
            }
            return null;
        }
          
    }
}
