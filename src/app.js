import express from "express"
import cors from "cors"
import cookieParser from "cookie-parser"

const app = express()

app.use(cors({
    origin:"*",
    credentials:true
}));

app.use(express.static("public"))
app.use(express.urlencoded({extended:true}))
app.use(express.json());
app.use(cookieParser());

//import routes
import userRoutes from "./routes/user.routes.js"
import riderRoutes from "./routes/rider.routes.js"

//routes declaration
app.use("/api/v1/users", userRoutes)
app.use("/api/v1/riders", riderRoutes)

export default app

