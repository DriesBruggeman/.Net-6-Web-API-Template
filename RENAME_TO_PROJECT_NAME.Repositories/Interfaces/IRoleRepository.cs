using RENAME_TO_PROJECT_NAME.Models.Roles;
using RENAME_TO_PROJECT_NAME.Models.Common;

namespace RENAME_TO_PROJECT_NAME.Repositories
{
    public interface IRoleRepository
    {
        Task<GetListModel<GetRoleModel>> GetRoles(int number, int page);
        Task<GetRoleModel> GetRole(Guid id);
        Task PutRole(Guid id, PutRoleModel putRoleModel);
    }
}
