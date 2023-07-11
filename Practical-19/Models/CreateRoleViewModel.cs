using System.ComponentModel.DataAnnotations;

namespace eCommerceCore.ViewModels
{
    public class CreateRoleViewModel
    {
        [Required]
        public string RoleName { get; set; }
    }
}
