using System.ComponentModel.DataAnnotations;

namespace RENAME_TO_PROJECT_NAME.Models.Roles
{
    public class BaseRoleModel
    {
        [StringLength(255)]
        public string Description { get; set; }

        public string RoleType { get; set; }
    }
}
