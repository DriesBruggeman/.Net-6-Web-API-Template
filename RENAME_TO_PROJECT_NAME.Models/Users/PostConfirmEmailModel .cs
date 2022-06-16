using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace RENAME_TO_PROJECT_NAME.Models.Users
{
    public class PostConfirmEmailModel
    {
        [Display(Name = "Email adres")]
        [Required(ErrorMessage = "Email adres is verplicht")]
        [EmailAddress(ErrorMessage = "Geen geldig email adres")]
        public string Email { get; set; }

        public string Token { get; set; }
    }
}
