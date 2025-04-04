import express from "express";
import passport from "passport";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import { prisma } from "../prismaClient.js";

dotenv.config();

const router = express.Router();

function generateRefId() {
  const randomPart = Math.random().toString(36).substring(2, 9).toUpperCase();
  return `NETTS${randomPart}`;
}

router.post("/register", async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      phone,
      state,
      city,
      pincode,
    } = req.body;

    if (
      !firstName ||
      !lastName ||
      !email ||
      !password ||
      !phone ||
      !state ||
      !city ||
      !pincode
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    let user = await prisma.user.findUnique({ where: { email } });
    if (user) {
      return res.status(400).json({ error: "Email already registered" });
    }

    user = await prisma.user.findUnique({ where: { phone } });
    if (user) {
      return res.status(400).json({ error: "Phone number already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const refId = generateRefId();

    const newUser = await prisma.user.create({
      data: {
        firstName,
        lastName,
        email,
        password: hashedPassword,
        phone,
        state,
        city,
        pincode,
        refId,
        coins: 0,
      },
    });

    res
      .status(201)
      .json({ message: "User registered successfully", user: newUser });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Local Login Endpoint
router.post("/login", (req, res, next) => {
  passport.authenticate(
    "local-login",
    { session: false },
    (err, user, info) => {
      if (err || !user) {
        return res
          .status(400)
          .json({ error: info ? info.message : "Login failed" });
      }
      const token = jwt.sign(
        { id: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "1h" },
      );
      res.json({ message: "Login successful", token, user });
    },
  )(req, res, next);
});

// Google OAuth Initiation
router.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] }),
);

// Google OAuth Callback
router.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    session: false,
    failureRedirect: "/login",
  }),
  (req, res) => {
    // Successful authentication, generate token and respond.
    const user = req.user;
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );
    // You can choose to redirect or send the token as JSON.
    res.json({ message: "Google login successful", token, user });
  },
);

// Session Endpoint (for checking current session)
router.get(
  "/session",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.json({ user: req.user });
  },
);

export default router;
