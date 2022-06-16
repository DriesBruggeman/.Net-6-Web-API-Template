using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace RENAME_TO_PROJECT_NAME.Models.Users
{
    public class PostResetPasswordModel
    {
        [Display(Name = "Email adres")]
        [Required(ErrorMessage = "Email adres is verplicht")]
        [EmailAddress(ErrorMessage = "Geen geldig email adres")]
        public string Email { get; set; }

        [Display(Name = "Nieuw Wachtwoord")]
        [Required(ErrorMessage = "Nieuw wachtwoord is verplicht")]
        [RegularExpression(@"^(?=.*\d.*)(?=.*[a-z].*)(?=.*[A-Z].*)(?=.*[^a-zA-Z0-9].*).{6,}$", ErrorMessage = "Wachtwoord is ministens 6 tekens met minstens 1 kleine en 1 grote letter, een cijfer en een teken")]
        public string Password { get; set; }

        [Display(Name = "Wachtwoord bevestigen")]
        [Required(ErrorMessage = "Wachtwoord bevestigen is verplicht")]
        [RegularExpression(@"^(?=.*\d.*)(?=.*[a-z].*)(?=.*[A-Z].*)(?=.*[^a-zA-Z0-9].*).{6,}$", ErrorMessage = "Wachtwoord is ministens 6 tekens met minstens 1 kleine en 1 grote letter, een cijfer en een teken")]
        public string ConfirmPassword { get; set; }

        public string Token { get; set; }
    }
}
