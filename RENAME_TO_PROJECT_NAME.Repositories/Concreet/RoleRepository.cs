using RENAME_TO_PROJECT_NAME.Data;
using RENAME_TO_PROJECT_NAME.Data.Entities;
using RENAME_TO_PROJECT_NAME.Models.Roles;
using RENAME_TO_PROJECT_NAME.Exceptions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Data;
using RENAME_TO_PROJECT_NAME.Repositories.Helpers;
using RENAME_TO_PROJECT_NAME.Models.Common;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace RENAME_TO_PROJECT_NAME.Repositories
{
    public class RoleRepository : IRoleRepository
    {
        private readonly AppDbContext _context;
        private readonly RoleManager<Role> _roleManager;
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly ClaimsPrincipal _user;

        public RoleRepository(AppDbContext context, RoleManager<Role> roleManager, IHttpContextAccessor contextAccessor)
        {
            _context = context;
            _roleManager = roleManager;
            _contextAccessor = contextAccessor;
            _user = contextAccessor.HttpContext.User;
        }

        public async Task<GetListModel<GetRoleModel>> GetRoles(int number, int page)
        {
           
            List<GetRoleModel> roles = await _context.Roles
            .OrderBy(x => x.Name)
            .Select(x => new GetRoleModel
            {
                Id = x.Id,
                Name = x.Name,
                RoleType = x.Type.ToString(),
                Description = x.Description
            })
            .AsNoTracking()
            .ToListAsync();

            if (roles.Count == 0)
            {
                throw new AppException("NotFoundException", "Geen rollen gevonden.", this.GetType().Name, "GetRoles", "404");
            }

            if (!_user.IsInRole("QrWalletAdmin")){
                roles.RemoveAll(r => r.Name.Equals("QrWalletAdmin"));
                roles.RemoveAll(r => r.Name.Equals("EventAdmin"));
            }

            var getRolesModel = MakeModel.MakeGetListModel(number, page, roles);

            return getRolesModel;
        }

        public async Task<GetRoleModel> GetRole(Guid id)
        {
         
            GetRoleModel role = await _context.Roles
            .Select(x => new GetRoleModel
            {
                Id = x.Id,
                Name = x.Name,
                RoleType = x.Type.ToString(),
                Description = x.Description
            })
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id);

            if (role == null)
            {
                throw new AppException("EntityException", "Rol niet gevonden.", this.GetType().Name, "GetRole", "404");
            }

            return role;
            
        }

        public async Task PutRole(Guid id, PutRoleModel putRoleModel)
        {
            
            Role role = await _context.Roles.FirstOrDefaultAsync(x => x.Id == id);

            if (role == null)
            {
                throw new AppException("NotFoundException", "Rol niet gevonden.", this.GetType().Name, "PutRole", "404");
            }

            role.Type = Enum.Parse<RoleType>(putRoleModel.RoleType);
            role.Description = putRoleModel.Description;

            IdentityResult result = await _roleManager.UpdateAsync(role);

            if (!result.Succeeded)
            {
                throw new AppException("IdentityException", result.Errors.First().Description, this.GetType().Name, "PutRole", "500");
            }
            
        }

        /*
        public async Task DeleteRole(Guid id)
        {
            try
            {
                Role role = await _context.Roles.FirstOrDefaultAsync(x => x.Id == id);

                if (role == null)
                {
                    throw new AppException("Role niet gevonden.", this.GetType().Name, "DeleteRole", "404");
                }

                IdentityResult result = await _roleManager.DeleteAsync(role);

                if (!result.Succeeded)
                {
                    throw new AppException(result.Errors.First().Description, this.GetType().Name, "DeleteRole", "400");
                }
            }
            catch (TicketingException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new DatabaseException(e.InnerException.Message, this.GetType().Name, "DeleteRole", "400");
            }
        }*/
    }
}
