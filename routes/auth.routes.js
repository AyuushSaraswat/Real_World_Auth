const express = require("express");

const {
  protectedController,
  publicController,
  logoutController,
  loginController,
  registerController,
  refreshAccessTokenController,
  logoutAllController,
} = require("../controllers/user.controller");

const authMiddleware = require("../middlewares/auth.middleware");

const roleMiddleware = require("../middlewares/role.middleware");

const router = express.Router();

router.post("/register", registerController);

router.post("/login", loginController);

router.post("/refresh", refreshAccessTokenController);

router.post("/logout", logoutController);

router.post("/logout-all", logoutAllController);

router.get("/public", publicController);

// USER + ADMIN BOTH CAN ACCESS
router.get("/protected",authMiddleware,roleMiddleware("user", "admin"),protectedController,
);

// ADMIN ONLY ROUTE
router.get("/admin", authMiddleware, roleMiddleware("admin"), (req, res) => {
  return res.status(200).json({
    success: true,
    message: "Welcome Admin",
    user: req.user,
  });
});

module.exports = router;
