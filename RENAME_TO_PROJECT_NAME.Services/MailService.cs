using Microsoft.Extensions.Options;
using RENAME_TO_PROJECT_NAME.Models;
using System.Net;
using System.Net.Mail;
using System.Web;

namespace RENAME_TO_PROJECT_NAME.Services
{
    public class MailService : IMailService
    {
        private readonly AppSettings _appSettings;
        private readonly NetworkCredential _credentials;

        public MailService(IOptions<AppSettings> appSettings)
        {
            _appSettings = appSettings.Value;
            _credentials = new NetworkCredential(_appSettings.EmailUser, _appSettings.EmailPassword);
        }

        private async Task Send(string from, string to, string subject, string body)
        {
        	using (var client = new SmtpClient(_appSettings.SmtpServer, _appSettings.SmtpPort)
            {
                Credentials = _credentials,
                EnableSsl = true
            })
            {
                using (var msg = new MailMessage(from, to, subject, body))
                {
                    msg.IsBodyHtml = true;
                    await client.SendMailAsync(msg);
                }
            }
        } 
    }
}
