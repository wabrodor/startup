const express =  require("express")
const cors =  require("cors")
const app =  express()

app.use(cors())
app.use(express.json())

app.get("/", (req, res) =>{
    res.send("hello word from express!!")
})
 app.get("/user", (req, res) =>{
    res.send("hey user!!!!")
 })

//  app.get("*", (req, res) =>{
//     res.send("error route")
//  })

module.exports =app