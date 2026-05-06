const express = require("express");
const app = express();
require("dotenv").config();

const connectDB = require("./config/db.js");
const cors = require("cors");
const cookieParser = require("cookie-parser");


const authRoutes = require("./routes/auth.routes");

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);
app.use("/api/auth", authRoutes);

// Test route
app.get("/", (req, res) => {
  res.send("Express server is started");
});

const PORT = process.env.PORT || 6000;

// Start server
const startServer = async () => {
  try {
    await connectDB();

    app.listen(PORT, () => {
      console.log(`App is running at ${PORT}`.bgGreen);
    });
  } catch (error) {
    console.error("Failed to start server:", error.message);
    process.exit(1);
  }
};

startServer();