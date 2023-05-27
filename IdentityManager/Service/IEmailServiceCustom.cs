namespace IdentityManager.Service
{
    public interface IEmailServiceCustom
    {
        Task SendEmailAsync(string toEmail, string subject, string body);
    }
}
