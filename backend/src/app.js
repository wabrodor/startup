const express = require("express")
const cors =  require("cors")
const errorHandler =  require("./middleware/ErrorHandler")
const app =  express()
const mainRoutes = require('./routes');
const testRoutes =  require("./routes")
const setupSwagger =  require("./swagger")
app.use(cors())

app.use(express.json())

app.use((req, res, next) => {
    if (req.method === 'POST' || req.method === 'PUT') {
        // Check content type first
        if (!req.is("json")) {
            return res.status(400).json({
                error: "Content type must be application/json"
            });
        }
        
        // Check if body is empty
        if (!req.body || Object.keys(req.body).length === 0) {
            return res.status(400).json({
                error: "Request body cannot be empty"
            });
        }
    }
    next();
});


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