using Microsoft.AspNetCore.Identity;
using RENAME_TO_PROJECT_NAME.Data.Entities;
using RENAME_TO_PROJECT_NAME.Data;
using Microsoft.Extensions.DependencyInjection;

namespace RENAME_TO_PROJECT_NAME.Data.Seeds
{
    public static class RoleSeeder
    {
        public static void Seed(IServiceProvider serviceProvider)
        {
            AppDbContext _context = serviceProvider.GetRequiredService<AppDbContext>();
            RoleManager<Role> _roleManager = serviceProvider.GetRequiredService<RoleManager<Role>>();

            if (_context.Roles.Count() > 0)
            {
                return;   // DB has been seeded
            }

            // Create "Status" roles
            // ============

            _ = _roleManager.CreateAsync(new Role { Name = "Administrator", Type= RoleType.STATUS, Description = "Administrator has full control over application." }).Result;
            _ = _roleManager.CreateAsync(new Role { Name = "User", Type = RoleType.STATUS, Description = "Normal application user." }).Result;

        }
    }
}
