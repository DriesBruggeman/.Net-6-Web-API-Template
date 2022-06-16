using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace RENAME_TO_PROJECT_NAME.Models.Users
{
    public class PostResendEmailModel
    {
        [Display(Name = "Email adres")]
        [Required(ErrorMessage = "Gelieve uw email adres in te vullen")]
        [EmailAddress(ErrorMessage = "Gelieve een geldig email adres op te geven")]
        public string Email { get; set; }
    }
}
