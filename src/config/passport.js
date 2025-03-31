import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import bcrypt from "bcryptjs";
import { prisma } from "../prismaClient.js";
import dotenv from "dotenv";

dotenv.config();

// Local Login Strategy
passport.use(
  "local-login",
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) return done(null, false, { message: "User not found" });
        if (!user.password)
          return done(null, false, {
            message: "User registered via social login",
          });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
          return done(null, false, { message: "Incorrect password" });

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    },
  ),
);

// Local Register Strategy (if needed)
passport.use(
  "local-register",
  new LocalStrategy(
    { usernameField: "email", passReqToCallback: true },
    async (req, email, password, done) => {
      try {
        const { firstName, lastName, phone, state, city, pincode } = req.body;

        let user = await prisma.user.findUnique({ where: { email } });
        if (user) {
          return done(null, false, { message: "Email already registered" });
        }

        user = await prisma.user.findUnique({ where: { phone } });
        if (user) {
          return done(null, false, {
            message: "Phone number already registered",
          });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

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
          },
        });

        return done(null, newUser);
      } catch (error) {
        return done(error);
      }
    },
  ),
);

// JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET,
};

passport.use(
  new JwtStrategy(jwtOptions, async (jwtPayload, done) => {
    try {
      const user = await prisma.user.findUnique({
        where: { id: jwtPayload.id },
      });
      if (user) return done(null, user);
      return done(null, false);
    } catch (error) {
      return done(error, false);
    }
  }),
);

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Find user by email (assuming email is available in profile)
        const email = profile.emails[0].value;
        let user = await prisma.user.findUnique({ where: { email } });

        // If user doesn't exist, create one with details from Google
        if (!user) {
          // Generate referral code using your existing function or inline logic
          const randomPart = Math.random()
            .toString(36)
            .substring(2, 9)
            .toUpperCase();
          const refId = `NETTS${randomPart}`;

          user = await prisma.user.create({
            data: {
              firstName: profile.name.givenName || "",
              lastName: profile.name.familyName || "",
              email,
              password: "", // No password as this is social login
              phone: "", // Optionally fill if available
              state: "",
              city: "",
              pincode: "",
              refId,
              coins: 0,
            },
          });
        }
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    },
  ),
);

// Serialize / Deserialize
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

export default passport;
