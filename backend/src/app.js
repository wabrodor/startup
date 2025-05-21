const express = require("express")
const cors =  require("cors")
const errorHandler =  require("./middleware/ErrorHandler")
const app =  express()
const mainRoutes = require('./routes');
const testRoutes =  require("./routes")
const setupSwagger =  require("./swagger")
app.use(cors())

app.use(express.json())
app.use((req, res, next) =>{
    if ((req.method === 'POST' || req.method === "PUT") && !req.is("json"))
    
        return res.status(400).json(({
            error: "Conten type must be application/json"
       
    }))
    next()

})


app.get("/", (req, res) =>{
    res.send("hello word from express!!")
})
 app.get("/user", (req, res) =>{
    res.send("hey user!!!!")
 })
 setupSwagger(app)
 
app.use("/api/v1/", mainRoutes)

app.use("api/v1", testRoutes)

app.use(errorHandler)

module.exports =app