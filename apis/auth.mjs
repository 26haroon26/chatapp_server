import express from "express";
import { userModel, otpModel } from "./../dbRepo/models.mjs";
import { stringToHash, varifyHash } from "bcrypt-inzi";
import jwt from "jsonwebtoken";
import { customAlphabet } from "nanoid";
import moment from "moment";
import SendEmail from "../forSendEmail/sendEmail.mjs";

const SECRET = process.env.SECRET || "topsecret";


const router = express.Router();

router.post("/signup", (req, res) => {
  let body = req.body;

  if (!body.firstName || !body.lastName || !body.email || !body.password) {
    res.status(400).send(
      `required fields missing, request example: 
                {
                    "firstName": "John",
                    "lastName": "Doe",
                    "email": "abc@abc.com",
                    "password": "12345"
                }`
    );
    return;
  }

  req.body.email = req.body.email.toLowerCase();

  // check if user already exist // query email user
  userModel.findOne({ email: body.email }, (err, user) => {
    if (!err) {
      if (user) {
        // user already exist
        res.status(400).send({
          message: "user already exist,, please try a different email",
        });
        return;
      } else {
        // user not already exist

        // bcrypt hash
        stringToHash(body.password).then((hashString) => {
          userModel.create(
            {
              firstName: body.firstName,
              lastName: body.lastName,
              email: body.email,
              password: hashString,
            },
            (err, result) => {
              if (!err) {
                res.status(201).send({ message: "user is created" });
              } else {
                res.status(500).send({ message: "internal server error" });
              }
            }
          );
        });
      }
    } else {
      res.status(500).send({ message: "db error in query" });
      return;
    }
  });
});

router.post("/login", (req, res) => {
  let body = req.body;
  body.email = body.email.toLowerCase();

  if (!body.email || !body.password) {
    // null check - undefined, "", 0 , false, null , NaN
    res.status(400).send(
      `required fields missing, request example: 
                {
                    "email": "abc@abc.com",
                    "password": "12345"
                }`
    );
    return;
  }

  userModel.findOne(
    { email: body.email },
    "firstName lastName email password",
    (err, data) => {
      if (!err) {
        if (data) {
          // user found
          varifyHash(body.password, data.password).then((isMatched) => {
            if (isMatched) {
              const token = jwt.sign(
                {
                  _id: data._id,
                  email: data.email,
                  iat: Math.floor(Date.now() / 1000) - 30,
                  exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
                },
                SECRET
              );

              res.cookie("Token", token, {
                maxAge: 86_400_000,
                httpOnly: true,
                sameSite: "none",
                secure: true,
              });

              res.send({
                message: "login successful",
                profile: {
                  email: data.email,
                  firstName: data.firstName,
                  lastName: data.lastName,
                  age: data.age,
                  _id: data._id,
                },
              });
              return;
            } else {
              res.status(401).send({ message: "Incorrect email or password" });
              return;
            }
          });
        } else {
          res.status(401).send({ message: "Incorrect email or password" });
          return;
        }
      } else {
        res.status(500).send({ message: "login failed, please try later" });
        return;
      }
    }
  );
});

router.post("/logout", (req, res) => {
  res.clearCookie("Token", {
    httpOnly: true,
    sameSite: "none",
    secure: true,
  });
  res.send({ message: "Logout successful" });
});

router.post("/forget-password", async (req, res) => {
  try {
    let body = req.body;
    body.email = body.email.toLowerCase();

    if (!body.email) {
      // null check - undefined, "", 0 , false, null , NaN
      res.status(400).send(
        `required fields missing, request example: 
                {
                    "email": "abc@abc.com",
                }`
      );
      return;
    }

    // check if user exist
    const user = await userModel
      .findOne({ email: body.email }, "firstName lastName email")
      .exec();

    if (!user) throw new Error("User not found");

    const nanoid = customAlphabet("1234567890", 5);
    const OTP = nanoid();
    const otpHash = await stringToHash(OTP);
    otpModel.create({
      otp: otpHash,
      email: body.email,
    });

    await SendEmail({
      email: user.email,
      subject: `Froget paswword Email`,
      text: `Your OTP code is here \n\n ${OTP} \n\n Please Don't Share this code`,
    });

    res.send({
      message: "OTP sent success",
    });
    return;
  } catch (error) {
    res.status(500).send({
      message: error.message,
    });
  }
});
router.post("/forget-password-2", async (req, res) => {
  try {
    let body = req.body;
    body.email = body.email.toLowerCase();

    if (!body.email || !body.otp || !body.newPassword) {
      // null check - undefined, "", 0 , false, null , NaN

      res.status(400).send(
        `required fields missing, request example: 
                {
                    "email": "abc@abc.com",
                    "otp": "12345",
                    "newPassword": "someSecretString",
                }`
      );
      return;
    }

    // check if otp exist
    const otpRecord = await otpModel
      .findOne({
        email: body.email,
      })
      .sort({ _id: -1 })
      .exec();

    if (!otpRecord) throw new Error("Invalid Opt");
    if (otpRecord.isUsed) throw new Error("Invalid Otp");

    await otpRecord.update({ isUsed: true }).exec();

    const now = moment();
    const optCreatedTime = moment(otpRecord.createdOn);
    const diffInMinutes = now.diff(optCreatedTime, "minutes");

    if (diffInMinutes >= 5) throw new Error("Invalid Otp");

    const isMatched = await varifyHash(body.otp, otpRecord.otp);
    if (!isMatched) throw new Error("Invalid OTP");

    const newHash = await stringToHash(body.newPassword);

    await userModel
      .updateOne({ email: body.email }, { password: newHash })
      .exec();

    // success
    res.send({
      message: "password updated success",
    });
    return;
  } catch (error) {
    res.status(500).send({
      message: error.message,
    });
  }
});

export default router;
