using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace RENAME_TO_PROJECT_NAME.Models.Users
{
    public class PatchUserModel
    {
        [Display(Name = "Huidig wachtwoord")]
        [Required(ErrorMessage = "Huidig wachtwoord is verplicht")]
        [RegularExpression(@"^(?=.*\d.*)(?=.*[a-z].*)(?=.*[A-Z].*)(?=.*[^a-zA-Z0-9].*).{6,}$", ErrorMessage = "Wachtwoord is ministens 6 tekens met minstens 1 kleine en 1 grote letter, een cijfer en een teken")]
        public string CurrentPassword { get; set; }

        [Display(Name = "Nieuw wachtwoord")]
        [Required(ErrorMessage = "Nieuw wachtwoord is verplicht")]
        [RegularExpression(@"^(?=.*\d.*)(?=.*[a-z].*)(?=.*[A-Z].*)(?=.*[^a-zA-Z0-9].*).{6,}$", ErrorMessage = "Wachtwoord is ministens 6 tekens met minstens 1 kleine en 1 grote letter, een cijfer en een teken")]
        public string NewPassword { get; set; }

        [Display(Name = "Nieuw wachtwoord bevestigen")]
        [Required(ErrorMessage = "Nieuw wachtwoord bevestigen is verplicht")]
        [RegularExpression(@"^(?=.*\d.*)(?=.*[a-z].*)(?=.*[A-Z].*)(?=.*[^a-zA-Z0-9].*).{6,}$", ErrorMessage = "Wachtwoord is ministens 6 tekens met minstens 1 kleine en 1 grote letter, een cijfer en een teken")]
        public string NewConfirmPassword { get; set; }
    }
}
