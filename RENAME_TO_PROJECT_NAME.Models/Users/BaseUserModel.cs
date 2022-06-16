using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace RENAME_TO_PROJECT_NAME.Models.Users
{
    public class BaseUserModel
    {
        [Display(Name = "Voornaam")]
        [Required(ErrorMessage = "Voornaam is verplicht")]
        [StringLength(60, ErrorMessage = "Voornaam mag niet langer zijn dan 60 tekens en is minstens 2 tekens", MinimumLength = 2)]
        public string Firstname { get; set; }

        [Display(Name = "Familienaam")]
        [Required(ErrorMessage = "Familienaam is verplicht")]
        [StringLength(60, ErrorMessage = "Familienaam mag niet langer zijn dan 60 tekens en is minstens 2 tekens", MinimumLength = 2)]
        public string Lastname { get; set; }

        [Display(Name = "Email adres")]
        [Required(ErrorMessage = "Email adres is verplicht")]
        [EmailAddress(ErrorMessage = "Geen geldig emailadres")]
        public string Email { get; set; }

        [Display(Name = "Invite code")]
        public string InviteCode { get; set; }

        public Guid? EventId { get; set; }

        public string PreferredLocale { get; set; }
    }
}
