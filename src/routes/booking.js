import express from "express";
import { prisma } from "../prismaClient.js";
import passport from "passport";

const router = express.Router();

router.post(
  "/",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const user = req.user;
      if (!user) {
        return res.status(401).json({ error: "User not logged in" });
      }

      const { manufacturer, model, battery } = req.body;
      if (!manufacturer || !model || !battery) {
        return res.status(400).json({ error: "Missing required fields" });
      }

      const preBooking = await prisma.preBooking.create({
        data: {
          manufacturer,
          model,
          battery,
          userId: user.id, // Assign the booking to the authenticated user
        },
      });

      res
        .status(201)
        .json({ message: "Pre-booking created successfully", preBooking });
    } catch (error) {
      console.error("Error creating pre-booking:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);
router.get(
  "/",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const user = req.user;

      const bookings = await prisma.preBooking.findMany({
        where: { userId: user.id },
        include: { user: true },
      });

      res.status(200).json({ bookings });
    } catch (error) {
      console.error("Error retrieving bookings:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);
export default router;
