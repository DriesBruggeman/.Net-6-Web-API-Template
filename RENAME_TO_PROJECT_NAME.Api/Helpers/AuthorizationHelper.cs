using System.Security.Claims;
using RENAME_TO_PROJECT_NAME.Data;
using RENAME_TO_PROJECT_NAME.Data.Entities;

namespace RENAME_TO_PROJECT_NAME.Api.Helpers
{
    public static class AuthorizationHelper
    {
        public static bool AuthorizeStaffMember(AppDbContext context, ClaimsPrincipal loggedInUser, string role, Guid eventId)
        {
            if (loggedInUser.IsInRole("Administrator"))
            {
                return true;
            }

            User user = context.Users.FirstOrDefault(u => u.Id.ToString().Equals(loggedInUser.Identity.Name));

            if (loggedInUser.IsInRole("StaffAdmin"))
            {
                return true;
            }

            return false;
        }

        public static bool AuthorizeAdmin(ClaimsPrincipal loggedInUser)
        {
            return loggedInUser.IsInRole("Administrator");
        }
    }
}
