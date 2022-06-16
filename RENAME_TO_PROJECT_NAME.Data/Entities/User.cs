using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace RENAME_TO_PROJECT_NAME.Data.Entities
{
    public class User : IdentityUser<Guid>
    {
        [Required]
        [StringLength(60)]
        public string Firstname { get; set; }
        [Required]
        [StringLength(60)]
        public string Lastname { get; set; }

        public ICollection<UserRole> UserRoles { get; set; }
        public ICollection<RefreshToken> RefreshTokens { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime UpdatedAt { get; set; } = DateTime.Now;
    }
}
