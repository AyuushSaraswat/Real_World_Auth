const roleMiddleware = (...allowedRoles) => {

  return (req, res, next) => {

    try {

      // get logged in user role
      const userRole = req.user.role;

      // check role permission
      if (!allowedRoles.includes(userRole)) {
        return res.status(403).json({
          success: false,
          message: "Access denied",
        });
      }

      // allow request
      next();

    } catch (error) {

      return res.status(500).json({
        success: false,
        message: "Internal Server Error",
      });
    }
  };
};

module.exports = roleMiddleware;