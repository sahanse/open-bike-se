import jwt from "jsonwebtoken"
import db from "../db/index.js"
import { asyncHandler } from "../utils/AsyncHandler.js"
import { ApiError } from "../utils/ApiError.js";

const verifyUser = asyncHandler(async(req, _, next)=>{
    try{
        const access_token = req.cookies?.accessToken || req.header("Authorization").replace("Bearer ", "");
        if(!access_token) throw new ApiError(400, "unauthorized access")

        // //verfiy access Token
        const verifyToken = await jwt.verify(access_token, process.env.ACCESS_TOKEN_SECRET);
        const user_id = verifyToken.user_id;

        //make sure user exist in db
        const checkExist = await db.query(
            `
            SELECT
            user_id,
            name,
            email,
            phone_number,
            user_image
            FROM users 
            WHERE user_id = $1
            `,[user_id]
        )
        if(checkExist.rowCount === 0) throw new ApiError(400, "unauthorized access")
        const user = checkExist.rows[0];
        req.user = user;
        next()
    }catch(error){
        console.log(' middlewares || auth.middleware || verifyUser || error', error);
        throw new ApiError(400, "unauthorized access")
    }
});

const authUser = asyncHandler(async(req, _, next)=>{
    try{
        const access_token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");
        
        if(access_token){
        const verifyToken = await jwt.verify(access_token, process.env.ACCESS_TOKEN_SECRET);
        const user_id = verifyToken.user_id;

        //make sure user exist in db
        const checkExist = await db.query(
            `
            SELECT
            user_id,
            name,
            email,
            phone_number,
            user_image
            FROM users 
            WHERE user_id = $1
            `,[user_id]
        )
        if(checkExist.rowCount === 0) throw new ApiError(400, "unauthorized access")
        const user = checkExist.rows[0];
        req.user = user;
        next()
      }

      if(!access_token){
        req.user=null;
        next()
      }
    }catch(error){
        console.log(' middlewares || auth.middleware || verifyUser || error', error);
        throw new ApiError(400, "unauthorized access")
    }
});


export {verifyUser, authUser}
