using Microsoft.AspNetCore.Identity;
using RENAME_TO_PROJECT_NAME.Data.Entities;
using RENAME_TO_PROJECT_NAME.Data;
using Microsoft.Extensions.DependencyInjection;

namespace RENAME_TO_PROJECT_NAME.Data.Seeds
{
    public static class UserSeeder
    {
        public static void Seed(IServiceProvider serviceProvider)
        {
            AppDbContext _context = serviceProvider.GetRequiredService<AppDbContext>();
            UserManager<User> _userManager = serviceProvider.GetRequiredService<UserManager<User>>();

            if (_context.Users.Count() > 0)
            {
                return;   // DB has been seeded
            }

            // Create users
            // ============

            var admin = new User
            {
                Id = Guid.Parse("f167b79a-67b3-4881-a3a6-7529327b2d2f"),
                Firstname = "Admin",
                Lastname = "User",
                Email = "dries@bruggeman.be",
                UserName = "dries@bruggeman.be",
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };
            _ = _userManager.CreateAsync(admin, "_Azerty123").Result;
            _ = _userManager.AddToRolesAsync(admin, new List<string> { "Administrator" }).Result;
        }
    }
}
