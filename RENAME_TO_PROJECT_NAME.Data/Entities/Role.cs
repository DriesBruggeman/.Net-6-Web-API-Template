using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace RENAME_TO_PROJECT_NAME.Data.Entities
{
    public class Role : IdentityRole<Guid>
    {
        [StringLength(255)]
        public string Description { get; set; }
        public RoleType Type { get; set; }
        public ICollection<UserRole> UserRoles { get; set; }
    }

    public enum RoleType
    {
        STATUS,
        PERMISSION
    }
}
