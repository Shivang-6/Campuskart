import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import express from "express";
import passport from "passport";
import Product from "../models/product.js";
import User from "../models/user.js";
dotenv.config();

const router = express.Router();

const getServerBaseUrl = (req) => {
  if (process.env.SERVER_URL) {
    return process.env.SERVER_URL.replace(/\/$/, "");
  }
  const forwardedProto = req.get("x-forwarded-proto");
  const protocol = (forwardedProto || req.protocol || "https").split(",")[0].trim();
  return `${protocol}://${req.get("host")}`;
};

router.get("/google", (req, res, next) => {
  const callbackURL = `${getServerBaseUrl(req)}/auth/google/callback`;
  passport.authenticate("google", {
    scope: ["profile", "email"],
    callbackURL,
  })(req, res, next);
});

router.get("/google/callback", (req, res, next) => {
  const successRedirect = process.env.CLIENT_URL
    ? process.env.CLIENT_URL.replace(/\/$/, '') + "/landing"
    : "http://localhost:5173/landing";
  const failureRedirect = process.env.CLIENT_URL
    ? process.env.CLIENT_URL.replace(/\/$/, '') + "/login?error=google_auth_failed"
    : "http://localhost:5173/login?error=google_auth_failed";

  passport.authenticate("google", (err, user, info) => {
    if (err) {
      console.error("Google OAuth callback error:", err);
      return res.redirect(failureRedirect);
    }

    if (!user) {
      console.warn("Google OAuth failed to return a user:", info);
      return res.redirect(failureRedirect);
    }

    req.logIn(user, (loginErr) => {
      if (loginErr) {
        console.error("Google OAuth session login error:", loginErr);
        return res.redirect(failureRedirect);
      }

      // Persist the session before redirect so the frontend can immediately
      // read the logged-in user via /auth/login/success.
      req.session.save((sessionErr) => {
        if (sessionErr) {
          console.error("Google OAuth session save error:", sessionErr);
          return res.redirect(failureRedirect);
        }
        return res.redirect(successRedirect);
      });
    });
  })(req, res, next);
});

router.get("/login/failed", (req, res) => {
  res.status(401).json({
    success: false,
    message: "Login failed"
  });
});

router.get("/login/success", (req, res) => {
  if (req.user) {
    res.status(200).json({
      success: true,
      message: "Login successful",
      user: req.user,
    });
  } else {
    res.status(403).json({ success: false, message: "Not authorized" });
  }
});

router.get("/logout", (req, res) => {
  req.logout(() => {
    res.json({ 
      success: true, 
      message: "Logged out successfully" 
    });
  });
});

// Traditional signup
router.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ success: false, message: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    req.login(user, (err) => {
      if (err) return res.status(500).json({ success: false, message: "Signup succeeded but login failed" });
      res.status(201).json({ success: true, message: "Signup successful", user });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Traditional login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }
    const user = await User.findOne({ email });
    if (!user || !user.password) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }
    req.login(user, (err) => {
      if (err) return res.status(500).json({ success: false, message: "Login failed" });
      res.status(200).json({ success: true, message: "Login successful", user });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.get("/", async (req, res) => {
  try {
    const products = await Product.find({ isAvailable: true, quantity: { $gt: 0 } })
      .sort({ createdAt: -1 })
      .populate('seller', 'name displayName googleId email');
    res.status(200).json({ success: true, products });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch products" });
  }
});

export default router;
