using System;
using System.Collections.Generic;
using System.Text;

namespace RENAME_TO_PROJECT_NAME.Models.Users
{
    public class PutUserModel : BaseUserModel
    {
        public Guid Id { get; set; }
        public ICollection<string> Roles { get; set; }
    }
}
