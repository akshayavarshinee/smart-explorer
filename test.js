import nodemailer from 'nodemailer';
import dotenv from "dotenv";
dotenv.config();

// Create transporter using Gmail SMTP
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true, // true for 465, false for 587

  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS // Use App Password, not your Gmail password
  }
});

// Define email options
const mailOptions = {
  from: '"Smart Explorer" <smart.explorer.hats@gmail.com>',
  to: 'akshaya.murugu@example.com',
  subject: 'Welcome to Smart Explorer 🧢',
  text: 'Hello! Thanks for joining us.',
  html: '<h2>Hello!</h2><p>Thanks for joining <strong>Smart Explorer</strong>.</p>'
};

// Send the email
try {
  transporter.verify((error, success) => {
  if (error) {
    console.error('❌ Transporter verification failed:', error);
  } else {
    console.log('✅ Server is ready to take messages');
  }
});
  const info = await transporter.sendMail(mailOptions);
  console.log('✅ Email sent:', info.messageId);
} catch (error) {
  console.error('❌ Error sending email:', error);
}