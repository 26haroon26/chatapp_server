import express from "express";
import path from "path";
import cors from "cors";
import authApis from "./apis/auth.mjs";
import check_login from "./apis/check_login.mjs";
import tweetApis from "./apis/tweet.mjs";
import cookieParser from "cookie-parser";

const app = express();
const port = process.env.PORT || 5001;

app.use(
  cors({
    origin: [
      "http://localhost:3000",'*',
    ],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

app.use("/api/v1", authApis);
app.use("/api/v1", check_login);

app.use("/api/v1", tweetApis);

const __dirname = path.resolve();
app.use("/", express.static(path.join(__dirname, "./web/build")));
app.use("*", express.static(path.join(__dirname, "./web/build")));

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});