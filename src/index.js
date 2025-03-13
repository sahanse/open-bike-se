import env from "dotenv"
import app from "./app.js"
import db from "./db/index.js"

env.config({
    path:"./.env"
})

db.connect().then(()=>{
    app.listen(process.env.EXPRESS_PORT || 8000, ()=>{
        console.log(`listening to port: ${process.env.EXPRESS_PORT}`)
    });
}).catch((error)=>{
    console.log(`error while connecting to db: ${error}`);
    process.exit(1)
})



