import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true
    },
    password: String,
    failedAttempts: { type: Number, default: 0 },
    isLocked: { type: Boolean, default: false },
    lockUntil: { type: Date },
    otp: String,
    otpExpires: Date
});

export default mongoose.model("User", UserSchema);