import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import bcrypt from "bcryptjs";
import { prisma } from "../prismaClient.js";
import dotenv from "dotenv";

dotenv.config();

// ----- Local Login Strategy -----
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

// ----- Local Register Strategy -----
// This strategy handles registration using extra fields from req.body.
passport.use(
  "local-register",
  new LocalStrategy(
    {
      usernameField: "email",
      passReqToCallback: true, // Enables access to req.body for additional fields.
    },
    async (req, email, password, done) => {
      try {
        const { firstName, lastName, phone, state, city, pincode } = req.body;

        // Check if a user already exists with the given email.
        let user = await prisma.user.findUnique({ where: { email } });
        if (user) {
          return done(null, false, { message: "Email already registered" });
        }

        // Optionally, check if a user exists with the same phone number.
        user = await prisma.user.findUnique({ where: { phone } });
        if (user) {
          return done(null, false, {
            message: "Phone number already registered",
          });
        }

        // Hash the password.
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user.
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

// ----- JWT Strategy -----
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

// ----- Session Serialization/Deserialization -----
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
