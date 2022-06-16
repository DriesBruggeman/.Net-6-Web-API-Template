namespace RENAME_TO_PROJECT_NAME.Models
{
    public class AppSettings
    {
        public string Secret { get; set; }
        public int JwtLifetime { get; set; }
        public int RefreshTokenLifetime { get; set; }
        public string[] AllowedCorsHosts { get; set; }
        public string EmailUser { get; set; }
        public string EmailPassword { get; set; }
        public string SmtpServer { get; set; }
        public int SmtpPort { get; set; }
        public string FrontendHost { get; set; }
        public string ImageHost { get; set; }
        public string FromEmail { get; set; }
        public string ResetURL { get; set; }
        public string ConfirmURL { get; set; }
        public string FacebookAppId { get; set; }
        public string FacebookAppSecret { get; set; }

    }
}

