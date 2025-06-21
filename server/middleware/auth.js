import User from "../models/User.js";
import jwt from "jsonwebtoken";

// Middleware to protect routes
export const protectRoute = async (req, res, next) => {
    try {
        const token = req.headers.token;
        if (!token) {
            return res.status(401).json({ success: false, message: "Token missing" });
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId).select("-password");
        if (!user) return res.status(400).json({
            success: false,
            message: "User not found"
        })
        req.user = user;
        next();
    } catch (error) {
        console.error(error.message);
        return res.json({
            success: false,
            message: error.message,
        });
    }
}