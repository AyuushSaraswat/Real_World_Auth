const jwt = require("jsonwebtoken");

const authMiddleware = async (req, res, next) => {
  try {

    // get authorization header
    const authHeader = req.headers.authorization;

    // check header exists
    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message: "Access token missing",
      });
    }

    // format => Bearer TOKEN
    const token = authHeader.split(" ")[1];

    // check token exists
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Invalid token format",
      });
    }

    // verify token
    const decoded = jwt.verify(
      token,
      process.env.ACCESS_SECRET
    );

    // attach user data to request
    req.user = decoded;

    // move to next middleware/controller
    next();

  } catch (error) {

    // token expired
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        message: "Access token expired",
      });
    }

    // invalid token
    return res.status(401).json({
      success: false,
      message: "Invalid access token",
    });
  }
};

module.exports = authMiddleware;