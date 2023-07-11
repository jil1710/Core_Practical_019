using Microsoft.AspNetCore.Identity;
using Practical_19.Models;

namespace Practical_19.Interfaces
{
    public interface IAuthentication
    {
       Task<string> LoginAsync(LoginViewModel login);
       Task<IdentityResult> RegisterAsync(RegisterViewModel register);
    }
}
