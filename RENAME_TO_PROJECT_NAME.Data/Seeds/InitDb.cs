using RENAME_TO_PROJECT_NAME.Data;
using RENAME_TO_PROJECT_NAME.Data.Entities;
using Microsoft.Extensions.DependencyInjection;

namespace RENAME_TO_PROJECT_NAME.Data.Seeds
{
    public static class InitDb
    {
        public static void Init(IServiceProvider serviceProvider)
        {
            AppDbContext _context = serviceProvider.GetRequiredService<AppDbContext>();

            Console.WriteLine("Resetting database");
            _ = _context.Database.EnsureDeletedAsync().Result;
            _ = _context.Database.EnsureCreatedAsync().Result;
        }
    }
}
