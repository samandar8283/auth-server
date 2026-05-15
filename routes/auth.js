import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import transporter from "../utils/sendEmail.js";

const router = express.Router();

// OTP generator
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

/* =========================
   REGISTER
========================= */
router.post("/register", async (req, res) => {
    try {
        const { email, password } = req.body;

        const exists = await User.findOne({ email });
        if (exists) {
            return res.status(400).json({ message: "Email orqali ro'yxatdan o'tilgan" });
        }

        const hashed = await bcrypt.hash(password, 10);

        await User.create({
            email,
            password: hashed
        });

        res.json({ message: "Foydalanuvchi muvaffaqiyatli yaratildi" });

    } catch (err) {
        res.status(500).json({ message: "Serverda xatolik yuz berdi" });
    }
});


/* =========================
   LOGIN (2FA OTP)
========================= */
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "Foydalanuvchi topilmadi" });
        }

        // lock check
        if (user.isLocked && user.lockUntil > Date.now()) {
            return res.status(403).json({ message: "Akkaunt bloklangan. Keyinroq urinib ko'ring." });
        }

        if (user.isLocked && user.lockUntil <= Date.now()) {
            user.isLocked = false;
            user.failedAttempts = 0;
        }

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            user.failedAttempts += 1;

            if (user.failedAttempts >= 3) {
                user.isLocked = true;
                user.lockUntil = Date.now() + 15 * 60 * 1000;
            }

            await user.save();
            return res.status(400).json({ message: "Login yoki parol xato" });
        }

        user.failedAttempts = 0;

        // OTP generate
        const otp = generateOTP();
        const hashedOtp = await bcrypt.hash(otp, 10);

        user.otp = hashedOtp;
        user.otpExpires = Date.now() + 5 * 60 * 1000;

        await user.save();

        await transporter.sendMail({
            from: process.env.EMAIL,
            to: user.email,
            subject: "Your OTP Code",
            text: `Your OTP is: ${otp}`
        });

        res.json({ requires2FA: true });

    } catch (err) {
        res.status(500).json({ message: "Serverda xatolik yuz berdi" });
        console.log(err);
    }
});


/* =========================
   VERIFY LOGIN OTP
========================= */
router.post("/verify", async (req, res) => {
    try {
        const { email, code } = req.body;

        const user = await User.findOne({ email });

        if (!user || !user.otp) {
            return res.status(400).json({ message: "OTP not found" });
        }

        if (user.otpExpires < Date.now()) {
            return res.status(400).json({ message: "OTP kod eskirgan" });
        }

        const valid = await bcrypt.compare(code, user.otp);

        if (!valid) {
            return res.status(400).json({ message: "OTP kod xato" });
        }

        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET || "secret",
            { expiresIn: "1h" }
        );

        user.otp = null;
        user.otpExpires = null;

        await user.save();

        res.json({ token });

    } catch (err) {
        res.status(500).json({ message: "Serverda xatolik yuz berdi" });
    }
});


/* =========================
   FORGOT PASSWORD
========================= */
router.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "Foydalanuvchi topilmadi" });
        }

        const otp = generateOTP();
        const hashedOtp = await bcrypt.hash(otp, 10);

        user.otp = hashedOtp;
        user.otpExpires = Date.now() + 5 * 60 * 1000;

        await user.save();

        await transporter.sendMail({
            from: process.env.EMAIL,
            to: user.email,
            subject: "Password Reset OTP",
            text: `Your reset OTP is: ${otp}`
        });

        res.json({ message: "OTP kod yuborildi" });

    } catch (err) {
        res.status(500).json({ message: "Serverda xatolik yuz berdi" });
        console.log(err);
    }
});


/* =========================
   VERIFY RESET OTP
========================= */
router.post("/verify-reset-otp", async (req, res) => {
    try {
        const { email, code } = req.body;

        const user = await User.findOne({ email });

        if (!user || !user.otp) {
            return res.status(400).json({ message: "OTP not found" });
        }

        if (user.otpExpires < Date.now()) {
            return res.status(400).json({ message: "OTP kod eskirgan" });
        }

        const valid = await bcrypt.compare(code, user.otp);

        if (!valid) {
            return res.status(400).json({ message: "OTP kod xato" });
        }

        res.json({ message: "OTP kod tasdiqlandi" });

    } catch (err) {
        res.status(500).json({ message: "Serverda xatolik yuz berdi" });
    }
});


/* =========================
   RESET PASSWORD
========================= */
router.post("/reset-password", async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: "Foydalanuvchi topilmadi" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;

        // clear OTP (VERY IMPORTANT)
        user.otp = null;
        user.otpExpires = null;

        await user.save();

        res.json({ message: "Password updated" });

    } catch (err) {
        res.status(500).json({ message: "Serverda xatolik yuz berdi" });
    }
});

export default router;