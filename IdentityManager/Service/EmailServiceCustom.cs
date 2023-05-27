using System.Net.Mail;
using System.Net;

namespace IdentityManager.Service
{
    public class EmailServiceCustom : IEmailServiceCustom
    {
        public async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            var smtpClient = new SmtpClient("smtp.gmail.com", 587)
            {
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential("sinthiya.bd001@gmail.com", "ogebfbhwdspazbqw"),
                EnableSsl = true
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress("sinthiya.bd001@gmail.com"),
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            };

            mailMessage.To.Add(toEmail);

            try
            {
                await smtpClient.SendMailAsync(mailMessage);
            }
            catch (Exception ex)
            {
                // Handle exception
                throw ex;
            }
            finally
            {
                mailMessage.Dispose();
                smtpClient.Dispose();
            }
        }

    }
}
