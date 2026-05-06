const jwt = require("jsonwebtoken");
const UserModel = require("../models/user.model");
const bcrypt = require("bcrypt");
const sendMail = require("../utils/sendMail");



// ================= REGISTER =================

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

    // response
    return res.status(201).json({
      success: true,
      message: "User registered successfully",
    });

  } catch (error) {

    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};



// ================= LOGIN =================

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
    const matchPass = await bcrypt.compare(
      password,
      user.password
    );

    if (!matchPass) {
      return res.status(401).json({
        success: false,
        message: "Password does not match",
      });
    }

    // jwt payload
    const payload = {
      id: user._id,
      email: user.email,
      role: user.role,
    };

    // generate access token
    const accessToken = jwt.sign(
      payload,
      process.env.ACCESS_SECRET,
      {
        expiresIn: process.env.ACCESS_EXPIRY,
      }
    );

    // generate refresh token
    const refreshToken = jwt.sign(
      payload,
      process.env.REFRESH_SECRET,
      {
        expiresIn: process.env.REFRESH_EXPIRY,
      }
    );

    // save refresh token in DB
    user.refreshTokens.push({
      token: refreshToken,
      expiresAt: new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000
      ),
    });

    await user.save();

    // send cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: false,
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

    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};



// ================= REFRESH ACCESS TOKEN =================

const refreshAccessTokenController = async (req, res) => {
  try {

    // get old refresh token
    const oldRefreshToken = req.cookies.refreshToken;

    if (!oldRefreshToken) {
      return res.status(401).json({
        success: false,
        message: "Please login",
      });
    }

    // verify refresh token
    const decoded = jwt.verify(
      oldRefreshToken,
      process.env.REFRESH_SECRET
    );

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
      (item) => item.token === oldRefreshToken
    );

    if (!tokenExists) {
      return res.status(401).json({
        success: false,
        message: "Invalid refresh token",
      });
    }

    // remove old refresh token
    user.refreshTokens = user.refreshTokens.filter(
      (item) => item.token !== oldRefreshToken
    );

    // payload
    const payload = {
      id: user._id,
      email: user.email,
      role: user.role,
    };

    // new access token
    const accessToken = jwt.sign(
      payload,
      process.env.ACCESS_SECRET,
      {
        expiresIn: process.env.ACCESS_EXPIRY,
      }
    );

    // new refresh token
    const newRefreshToken = jwt.sign(
      payload,
      process.env.REFRESH_SECRET,
      {
        expiresIn: process.env.REFRESH_EXPIRY,
      }
    );

    // save new refresh token
    user.refreshTokens.push({
      token: newRefreshToken,
      expiresAt: new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000
      ),
    });

    await user.save();

    // send cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // response
    return res.status(200).json({
      success: true,
      message: "Tokens refreshed successfully",
      accessToken,
    });

  } catch (error) {

    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};



// ================= LOGOUT =================

const logoutController = async (req, res) => {
  try {

    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: "Refresh token not found",
      });
    }

    // find user
    const user = await UserModel.findOne({
      "refreshTokens.token": refreshToken,
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // remove current token
    user.refreshTokens = user.refreshTokens.filter(
      (item) => item.token !== refreshToken
    );

    await user.save();

    // clear cookie
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: false,
      sameSite: "Strict",
    });

    return res.status(200).json({
      success: true,
      message: "Logout successful",
    });

  } catch (error) {

    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};



// ================= LOGOUT ALL =================

const logoutAllController = async (req, res) => {
  try {

    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: "Refresh token not found",
      });
    }

    // find user
    const user = await UserModel.findOne({
      "refreshTokens.token": refreshToken,
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // remove all refresh tokens
    user.refreshTokens = [];

    await user.save();

    // clear cookie
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: false,
      sameSite: "Strict",
    });

    return res.status(200).json({
      success: true,
      message: "Logged out from all devices",
    });

  } catch (error) {

    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};



// ================= FORGOT PASSWORD =================

const forgotPasswordController = async (req, res) => {
  try {

    const { email } = req.body;

    // validate email
    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    // find user
    const user = await UserModel.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // generate otp
    const otp = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    // save otp
    user.resetOtp = otp;

    // expiry => 10 mins
    user.resetOtpExpiry = new Date(
      Date.now() + 10 * 60 * 1000
    );

    await user.save();

    // send email
    await sendMail(
      email,
      "Password Reset OTP",
      `Your OTP is ${otp}`
    );

    return res.status(200).json({
      success: true,
      message: "OTP sent successfully",
    });

  } catch (error) {

    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};



// ================= RESET PASSWORD =================

const resetPasswordController = async (req, res) => {
  try {

    const { email, otp, newPassword } = req.body;

    // validate input
    if (!email || !otp || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    // find user
    const user = await UserModel.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // verify otp
    if (user.resetOtp !== otp) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    // verify otp expiry
    if (user.resetOtpExpiry < new Date()) {
      return res.status(400).json({
        success: false,
        message: "OTP expired",
      });
    }

    // hash new password
    const hashedPassword = await bcrypt.hash(
      newPassword,
      10
    );

    // update password
    user.password = hashedPassword;

    // clear otp
    user.resetOtp = null;
    user.resetOtpExpiry = null;

    // logout all sessions
    user.refreshTokens = [];

    await user.save();

    return res.status(200).json({
      success: true,
      message: "Password reset successful",
    });

  } catch (error) {

    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};



// ================= PUBLIC =================

const publicController = (req, res) => {
  try {

    return res.status(200).json({
      success: true,
      message: "Welcome to landing page",
    });

  } catch (error) {

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};



// ================= PROTECTED =================

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
  forgotPasswordController,
  resetPasswordController,
  publicController,
  protectedController,
};