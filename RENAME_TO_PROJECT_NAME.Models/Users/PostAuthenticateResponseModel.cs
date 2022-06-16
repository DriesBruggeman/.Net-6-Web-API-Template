using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace RENAME_TO_PROJECT_NAME.Models.Users
{
    public class PostAuthenticateResponseModel
    {
        public Guid Id { get; set; }
        public string Firstname { get; set; }
        public string Lastname { get; set; }
        public string Email { get; set; }
        public string JwtToken { get; set; }
        public ICollection<string> Roles { get; set; }

        [JsonIgnore] // refresh token is returned in http only cookie
        public string RefreshToken { get; set; }
    }
}
