const express = require('express');
const router = express.Router();

const User = require("../models/User.model.js")
const bcrypt = require("bcryptjs")
// ... aqui nuestras rutas de auth


// GET "/auth/signup" => Renderizar un formulario de registro
router.get("/signup", (req, res, next) => {
  res.render("auth/signup.hbs")
})


// POST "/auth/signup" => Recibir la indo del usuario y crerlo en la BD
router.post("/signup", async (req, res, next) => {
  console.log(req.body)

  // OPCIONALMENTE podemos destructurar los valores de los campos
  const { username, password } = req.body

  // Validaciónes de Servidor (Backend)

  // Que todos los campos tengan informacion (correo y contraseña)
  if (username === "" || password === "") {
    console.log("el username o la contraseña estan vacios")
    res.render("auth/signup.hbs", {
      errorMessage: "Los campos de username y contraseña son obligatorios",
      // previousData: req.body // ejemplo de enviar los valores anteriores luego del error
    })
    return // cuando esto ocurra, deten la ejecución de la ruta (funcion) 
  }

  // validación de contraseña
  const regexPattern = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/gm
  if (regexPattern.test(password) === false) {
    res.render("auth/signup.hbs", {
      errorMessage: "La contraseña no es suficientemente fuerte. Necesita al menos, una mayuscula, una minuscula, un caracter especial y minimo 8 caracteres.",
    })
    return // cuando esto ocurra, deten la ejecución de la ruta (funcion) 
  }

  try {
    // que no existan usuarios con el mismo nombre de usuario
    const foundUser = await User.findOne({ username: username })
    // si consigue el usuario. foundUser será el usuario
    // si no lo consigue el usuario. foundUser será null
    if (foundUser !== null) {
      res.render("auth/signup.hbs", {
        errorMessage: "Ese nombre de usuario ya existe",
      })
      return // cuando esto ocurra, deten la ejecución de la ruta (funcion) 
    } // todo probar la ruta cuando tengamos usuarios en la BD

    // vamos a encriptar la contraseña
    const salt = await bcrypt.genSalt(12)
    const hashPassword = await bcrypt.hash(password, salt)
    console.log(hashPassword)

    // ya todo bien! vamos a crear el usuario en la BD
    await User.create({
      username: username,
      password: hashPassword
    })

    // TEST (si todo sale bien)
    res.redirect("/auth/login")

  } catch (error) {
    next(error)
  }
})

// GET "/auth/login" => Renderizar el formulario de acceso a la pagina
router.get("/login", (req, res, next) => {
  res.render("auth/login.hbs")
})

// POST "/auth/login" => Recibir las credenciales del usuario y validar su identidad (autenticación)
router.post("/login", async (req, res, next) => {
  console.log(req.body)

 
  if (req.body.username === "" || req.body.password === "") {
    res.render("auth/login.hbs", {
      errorMessage: "Los campos de usuaruo y contraseña son obligatorios",
    })
    return 
  }

  try {
    // validar que el usuario existe en la base de datos
    const foundUser = await User.findOne({username: req.body.username})
    if (foundUser === null) {
      res.render("auth/login.hbs", {
        errorMessage: "Usuario no registrado",
      })
      return // cuando esto ocurra, deten la ejecución de la ruta (funcion) 
    }
    console.log(foundUser)
    
  
    // validar que la contraseña sea la correcta
    const isPasswordCorrect = await bcrypt.compare(req.body.password, foundUser.password)
    console.log(isPasswordCorrect)
    if (isPasswordCorrect === false) {
      res.render("auth/login.hbs", {
        errorMessage: "Contraseña no valida",
        username: req.body.username
      })
      return // cuando esto ocurra, deten la ejecución de la ruta (funcion) 
    }

    // a a partir de este punto ya hemos autenticado al usuario
    // 1. crear una sesion activa del usuario
    // 2. constantemente verificar en las rutas privadas que el usuario tenga dicha sesion activa
    // todo crea la sesión

    req.session.user = foundUser; // se crea la sesión
    // A partir de este momento tendremos acceso a req.session.user para saber quien está haciendo las llamadas al servidor

    req.session.save(() => {
      // Despues de que la sesión se crea correctamente, entonces redirije a una pagina privada
      res.redirect("/profile")
    })

    
  } catch (error) {
    next(error)
  }
})




module.exports = router;
