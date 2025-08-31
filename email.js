import Brevo from 'sib-api-v3-sdk';

// Initialize client
const defaultClient = Brevo.ApiClient.instance;
const apiKey = defaultClient.authentications['api-key'];
apiKey.apiKey = process.env.BREVO_API_KEY; // put your API key in .env

// Create transactional email API instance
const tranEmailApi = new Brevo.TransactionalEmailsApi();

// Function to send email
export async function sendInvite(toEmail, inviter, inviter_email) {
  try {
    const sendSmtpEmail = {
      sender: { email: process.env.EMAIL_USER, name: inviter }, // must be verified sender
      to: [{ email: toEmail }],
      subject: `${inviter} invited you to join Smart Explorer!`,
      htmlContent: `
        <h3>You're Invited!</h3>
        <p><strong>${inviter_email}</strong> has invited you to join Smart Explorer.</p>
        <p>Click <a href='http://localhost:3000/join'>here</a> to join the group.</p>
      `
    };

    const response = await tranEmailApi.sendTransacEmail(sendSmtpEmail);
    console.log("✅ Email sent:", response);
    return true;
  } catch (error) {
    console.error("❌ Failed to send email:", error.response?.body || error);
    return false;
  }
}
