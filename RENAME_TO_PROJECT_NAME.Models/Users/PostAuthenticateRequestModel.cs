using System.ComponentModel.DataAnnotations;

namespace  RENAME_TO_PROJECT_NAME.Models.Users
{
    public class PostAuthenticateRequestModel
    {
        [Display(Name = "Email adres")]
        [Required(ErrorMessage = "{0} is verplicht")]
        [EmailAddress(ErrorMessage = "Geen geldig email adres")]
        public string Email { get; set; }

        [Display(Name = "Wachtwoord")]
        [Required(ErrorMessage = "{0} is verplicht")]
        [RegularExpression(@"^(?=.*\d.*)(?=.*[a-z].*)(?=.*[A-Z].*)(?=.*[^a-zA-Z0-9].*).{6,}$", ErrorMessage = "Wachtwoord is ministens 6 tekens met minstens 1 kleine en 1 grote letter, een cijfer en een teken")]
        public string Password { get; set; }
    }
}

