import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import bcrypt from "bcryptjs";
import { prisma } from "../prismaClient.js";
import dotenv from "dotenv";

dotenv.config();

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

passport.use(
  "local-register",
  new LocalStrategy(
    {
      usernameField: "email",
      passReqToCallback: true,
    },
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
