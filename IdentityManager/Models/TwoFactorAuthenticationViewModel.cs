namespace IdentityManager.Models
{
	public class TwoFactorAuthenticationViewModel
	{
		public string Code { get; set; }	//For Login
		public string Token { get; set; }	//For Register
		public string QRCodeUrl { get; set; }   //For Register
	}
}
