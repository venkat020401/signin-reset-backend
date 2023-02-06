const express = require("express");
const app = express();
const mongodb = require("mongodb");
const dotenv = require("dotenv").config();
const mongoclient = mongodb.MongoClient;
const URL = process.env.DB;
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const SECURT = process.env.jwt_secret;
const rn = require("random-number");
const client_url = "http://localhost:3000"

const options = {
  min: 1000,
  max: 9999,
  integer: true,
};

//Middleware
app.use(express.json());
app.use(
  cors({
    origin: client_url,
  })
);

// Register
app.post("/register", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("registrations");
    const collection = db.collection("datas");

    const salt1 = await bcrypt.genSalt(10);
    const hash1 = await bcrypt.hash(req.body.password, salt1);
    req.body.password = hash1;

    const salt2 = await bcrypt.genSalt(10);
    const hash2 = await bcrypt.hash(req.body.confirm_password, salt2);
    req.body.confirm_password = hash2;

    const users = await collection.insertOne(req.body);
    await connection.close();

    res.json(users);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("registrations");
    const collection = db.collection("datas");
    const user = await collection.findOne({ email: req.body.email });
    console.log(user);
    if (user == null) {
      res.status(200).json({ message: "User not found", token });
    } else if (user) {
      const compare = await bcrypt.compare(req.body.password, user.password);
      if (compare) {
        const token = jwt.sign({ id: user._id }, SECURT);
        res.json({ message: "Login success" });
      } else {
        res.status(200).json({ message: "email/password wrong", token });
      }
    } else {
      res.json({ message: "Email / Password Is Wrong" });
    }

    await connection.close();
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

// Email config
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD,
  },
});

// Forgot Password mail sent
app.post("/sendpasswordlink", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("registrations");
    const collection = db.collection("datas");
    const userfind = await collection.findOne({ email: req.body.email });
    if (userfind) {
      let randomnum = rn(options);
      const setrandomnum = await collection.findOneAndUpdate(
        { email: req.body.email },
        {
          $set: {
            rnum: randomnum,
          },
        }
      );

      if (setrandomnum) {
        console.log(setrandomnum);
        const mailOptions = {
          from: process.env.EMAIL,
          to: req.body.email,
          subject: "Sending Email For password Reset",
          html: `<b>Please <a href='${client_url}/verify-user/${setrandomnum.value._id}/${randomnum}'> Click here</a> to reset your password</b>`,
        };
        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            res.status(401).json({ status: 401, message: "email not send" });
          } else {
            res.status(201).json({ status: 201, message: "Email sent Succsfully" });
          }
        });
      }
    } else {
      res.status(401).json({ status: 401, message: "user not send" });
    }
  } catch (error) {
    console.log("err", error);
  }
});

//verify user to forgot password
app.post("/verify-user/:id/:randomnum", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("registrations");
    const collection = db.collection("datas");
    const userfind = await collection.findOne({
      _id: mongodb.ObjectId(req.params.id),
    });

    if (userfind.rnum == req.params.randomnum) {
      res.status(200).json({ message: "user verified" });
    } else {
      res.status(400).json({ message: "Invalid url" });
    }
    await connection.close();
  } catch (error) {
    console.log(error);
  }
});

//Update new password
app.put("/password-update/:id", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("registrations");
    const collection = db.collection("datas");

    const salt1 = await bcrypt.genSalt(10);
    const hash1 = await bcrypt.hash(req.body.password, salt1);
    req.body.password = hash1;

    const salt2 = await bcrypt.genSalt(10);
    const hash2 = await bcrypt.hash(req.body.confirm_password, salt2);
    req.body.confirm_password = hash2;

    const users = await collection.findOneAndUpdate(
      { _id: mongodb.ObjectId(req.params.id) },
      {
        $set: {
          password: hash1,
          confirm_password: hash2,
        },
      }
    );
    await connection.close();
    res.json({ message: "Password updated successfully" });
  } catch (error) {
    console.log(error);
  }
});

// Set port.
app.listen(8000);
