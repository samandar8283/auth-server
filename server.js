import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.js";

dotenv.config();

const app = express();

app.use(cors({
    origin: [
        "http://localhost:5173",
        "https://your-netlify-site.netlify.app"
    ],
    credentials: true
}));

app.use(express.json());

app.use("/api", authRoutes);

// MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("DB connected"))
    .catch(err => console.log(err));

// PORT FIX (ENG MUHIM)
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});