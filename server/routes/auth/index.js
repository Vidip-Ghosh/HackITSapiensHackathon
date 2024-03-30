import express from "express";
import zod from "zod";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client"

const router = express.Router();
const prisma = new PrismaClient()

const userSignUpSchema = zod.object({
  username: zod.string(),
  email: zod.string(),
  password: zod.string(),
});

router.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    console.log(req.body);

    const result = userSignUpSchema.safeParse(req.body);
    if (result.success !== true) {
      return res.status(403).json({
        error: "Invalid Form Details",
      });
    }

    const isExisitingUser = await prisma.user.findFirst({
      where: {
        email: email,
        username: username,
      },
    });

    if (isExisitingUser !== null) {
      return res.status(403).json({
        error: "User already Exists",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await prisma.user.create({
      data: {
        username: username,
        email: email,
        password: hashedPassword,
      },
    });

    if (newUser) {
      const token = jwt.sign({ payload: username }, process.env.JWT_SECRET);

      return res.status(200).json({
        message: "Successfully Signed Up",
        username: newUser.username,
        token: token,
      });
    }
  } catch (error) {
    console.log(error)
    res.status(500).json({
      error: "Internal Server Error",
    });
  }
});

export default router;
