import sgMail from "@sendgrid/mail";
import dotenv from "dotenv";

dotenv.config();

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

export const sendEmail = async ({ to, subject, text }) => {
    try {
        const msg = {
            to,
            from: process.env.EMAIL_FROM,
            subject,
            text,
        };

        const result = await sgMail.send(msg);
        console.log("EMAIL SENT:", result[0].statusCode);

        return result;
    } catch (err) {
        console.log("SENDGRID ERROR:", err.response?.body || err);
        throw err;
    }
};