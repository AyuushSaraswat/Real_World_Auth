const jwt = require("jsonwebtoken");
const UserModel = require("../models/user.model");
const bcrypt = require("bcrypt");

const registerController = async (req, res) => {
  try {
    const { userName, email, password } = req.body;

    // validate input
    if (!userName || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    // check existing user
    const exist = await UserModel.findOne({ email });

    if (exist) {
      return res.status(409).json({
        success: false,
        message: "User already registered",
      });
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // create user
    await UserModel.create({
      userName,
      email,
      password: hashedPassword,
    });

    // success response
    return res.status(201).json({
      success: true,
      message: "User registered successfully",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};

const loginController = async (req, res) => {
  try {
    const { email, password } = req.body;

    // validate input
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    // check user
    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "You must register first",
      });
    }

    // compare password
    const matchPass = await bcrypt.compare(password, user.password);

    if (!matchPass) {
      return res.status(401).json({
        success: false,
        message: "Password does not match! Try again",
      });
    }

    // payload
    const payload = {
      id: user._id,
      email: user.email,
      role: user.role,
    };

    // generate tokens
    const accessToken = jwt.sign(payload, process.env.ACCESS_SECRET, {
      expiresIn: process.env.ACCESS_EXPIRY,
    });

    const refreshToken = jwt.sign(payload, process.env.REFRESH_SECRET, {
      expiresIn: process.env.REFRESH_EXPIRY,
    });

    // store refresh token in DB
    user.refreshTokens.push({
      token: refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    await user.save();

    // set cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: false, // set true in production (HTTPS)
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // response
    return res.status(200).json({
      success: true,
      message: "Login successful",
      accessToken,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};

const refreshAccessTokenController = async (req, res) => {
  try {
    // old refresh token from cookie
    const oldRefreshToken = req.cookies.refreshToken;

    if (!oldRefreshToken) {
      return res.status(401).json({
        success: false,
        message: "Please login ",
      });
    }

    // verify old refresh token
    const decoded = jwt.verify(oldRefreshToken, process.env.REFRESH_SECRET);

    // find user
    const user = await UserModel.findById(decoded.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // check token exists in DB
    const tokenExists = user.refreshTokens.find(
      (item) => item.token === oldRefreshToken,
    );

    if (!tokenExists) {
      return res.status(401).json({
        success: false,
        message: "Invalid refresh token",
      });
    }

    // REMOVE old refresh token (rotation)
    user.refreshTokens = user.refreshTokens.filter(
      (item) => item.token !== oldRefreshToken,
    );

    // payload
    const payload = {
      id: user._id,
      email: user.email,
      role: user.role,
    };

    // generate new access token
    const accessToken = jwt.sign(payload, process.env.ACCESS_SECRET, {
      expiresIn: process.env.ACCESS_EXPIRY,
    });

    // generate new refresh token
    const newRefreshToken = jwt.sign(payload, process.env.REFRESH_SECRET, {
      expiresIn: process.env.REFRESH_EXPIRY,
    });

    // store new refresh token
    user.refreshTokens.push({
      token: newRefreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    // save updated user
    await user.save();

    // send new refresh token cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: false, // true in production
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // send new access token
    return res.status(200).json({
      success: true,
      message: "Tokens refreshed successfully",
      accessToken,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};

const logoutController = async (req, res) => {
  try {
    // get refresh token from cookie
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: "Refresh token not found",
      });
    }

    // find user containing this refresh token
    const user = await UserModel.findOne({
      "refreshTokens.token": refreshToken,
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // remove current refresh token
    user.refreshTokens = user.refreshTokens.filter(
      (item) => item.token !== refreshToken,
    );

    // save updated user
    await user.save();

    // clear cookie
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: false, // true in production
      sameSite: "Strict",
    });

    // response
    return res.status(200).json({
      success: true,
      message: "Logout successful",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};

const logoutAllController = async (req, res) => {
  try {
    // get current refresh token from cookie
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: "Refresh token not found",
      });
    }

    // find user with this refresh token
    const user = await UserModel.findOne({
      "refreshTokens.token": refreshToken,
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // REMOVE ALL REFRESH TOKENS
    user.refreshTokens = [];

    // save updated user
    await user.save();

    // clear cookie
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: false, // true in production
      sameSite: "Strict",
    });

    // response
    return res.status(200).json({
      success: true,
      message: "Logged out from all devices successfully",
    });
  } catch (error) {
    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};

const publicController = (req, res) => {
  try {
    res.status(200).json({
      success: true,
      message: "Welcome to landing page",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};

const protectedController = (req, res) => {
  try {
    return res.status(200).json({
      success: true,
      message: "Protected route accessed",
      user: req.user,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};

module.exports = {
  registerController,
  loginController,
  refreshAccessTokenController,
  logoutController,
  logoutAllController,
  publicController,
  protectedController,
};
