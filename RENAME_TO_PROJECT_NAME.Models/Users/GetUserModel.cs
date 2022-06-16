namespace RENAME_TO_PROJECT_NAME.Models.Users
{
    public class GetUserModel : BaseUserModel
    {
        public Guid Id { get; set; }

        public ICollection<string> Roles { get; set; }

        public bool EmailConfirmed { get; set; }
    }
}
