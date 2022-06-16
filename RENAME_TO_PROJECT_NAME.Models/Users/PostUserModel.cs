using System.ComponentModel.DataAnnotations;


namespace RENAME_TO_PROJECT_NAME.Models.Users
{
    public class PostUserModel : BaseUserModel
    {
        [Display(Name = "Wachtwoord")]
        [Required(ErrorMessage = "Wachtwoord is verplicht")]
        [RegularExpression(@"^(?=.*\d.*)(?=.*[a-z].*)(?=.*[A-Z].*)(?=.*[^a-zA-Z0-9].*).{6,}$", ErrorMessage = "Wachtwoord is ministens 6 tekens met minstens 1 kleine en 1 grote letter, een cijfer en een teken")]
        public string Password { get; set; }

        [Display(Name = "Wachtwoord bevestigen")]
        [Required(ErrorMessage = "Wachtwoord bevestigen is verplicht")]
        [RegularExpression(@"^(?=.*\d.*)(?=.*[a-z].*)(?=.*[A-Z].*)(?=.*[^a-zA-Z0-9].*).{6,}$", ErrorMessage = "Wachtwoord is ministens 6 tekens met minstens 1 kleine en 1 grote letter, een cijfer en een teken")]
        public string ConfirmPassword { get; set; }

        public ICollection<string> Roles { get; set; }
    }
}
