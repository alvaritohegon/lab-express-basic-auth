const express = require('express');
const router = express.Router();

const isLoggedIn = require("../middlewares/auth.middlewares.js")

// ... aqui van rutas completamente privadas. solo accesibles a usuarios registrados
router.get("/", isLoggedIn, (req, res, next) => {

  console.log("quien me hace la llamada", req.session.user)

  res.render("profile/dashboard.hbs")
})


module.exports = router;