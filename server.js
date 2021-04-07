const express = require("express");
const app = express();
const dotenv = require("dotenv");
const mongoose = require("mongoose");
// Import Routes
const authRoute = require("./routes/auth");
const postsRoute = require("./routes/posts");

dotenv.config();

// Connect to DB
mongoose.connect(
  process.env.DB_CONNECT,
  { useNewUrlParser: true, useUnifiedTopology: true },
  () => {
    console.log("connected to db");
  }
);

// Middlewares
app.use(express.json());
// Route
app.use("/api/user", authRoute);
app.use("/api/posts", postsRoute);

app.get("/", (req, res) => {
  res.send("We are on home");
});

// connect to db

app.listen(3000, () => console.log("Listens at port 3000"));
