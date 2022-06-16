using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace RENAME_TO_PROJECT_NAME.Models.Roles
{
    public class GetRoleModel : BaseRoleModel
    {
        public Guid Id { get; set; }

        [Display(Name = "Naam")]
        public string Name { get; set; }

        [JsonIgnore]
        public bool Checked { get; set; }
    }
}
