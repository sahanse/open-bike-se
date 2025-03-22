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
            phone,
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

const verifyRider = asyncHandler(async(req, _, next)=>{
    try{
        const access_token = req.cookies?.riderAccessToken || req.header("Authorization").replace("Bearer ", "");
        if(!access_token) throw new ApiError(400, "unauthorized access")

        // //verfiy access Token
        const verifyToken = await jwt.verify(access_token, process.env.ACCESS_TOKEN_SECRET);
        const rider_id = verifyToken.rider_id;

        //make sure user exist in db
        const checkExist = await db.query(
            `
            SELECT
            rider_id,
            name,
            email,
            phone,
            rider_image
            FROM riders
            WHERE rider_id = $1
            `,[rider_id]
        )
        if(checkExist.rowCount === 0) throw new ApiError(400, "unauthorized access")
        const rider = checkExist.rows[0];
        req.rider = rider;
        next()
    }catch(error){
        console.log(' middlewares || auth.middleware || verifyUser || error', error);
        throw new ApiError(400, "unauthorized access")
    }
});

const verifyAccAuth = asyncHandler(async(req, _, next)=>{
    
    try{
        const access_token = req.cookies?.riderAccessToken || req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");
        
        if(access_token){
            //verfiy access Token
        const verifyToken = await jwt.verify(access_token, process.env.ACCESS_TOKEN_SECRET);
    
        let requester_type = null;
        let requester_table = null;
        let requester_id_type = null;

        if(verifyToken.user_id){
            requester_type = "user";
            requester_table = "users"
            requester_id_type ="user_id"
        }
        if(verifyToken.rider_id){
            requester_type = "rider"
            requester_table = "riders"
            requester_id_type = "rider_id"
        } 

        let requester_id = verifyToken[requester_id_type];
        
        //make sure user exist in db
        const checkExist = await db.query(
            `
            SELECT
            email
            FROM ${requester_table}
            WHERE ${requester_id_type} = $1
            `,[requester_id]
        )
        if(checkExist.rowCount === 0) throw new ApiError(400, "unauthorized access")
        const data = {
             requester:requester_type,
             requester_table,
             id:requester_id,
             email: checkExist.rows[0].email
         }
         req.auth_data = data;
        }
        next()
    }catch(error){
        console.log(' middlewares || auth.middleware || verifyUser || error', error);
        throw new ApiError(400, "unauthorized access 1")
    }
});

export {verifyUser, verifyRider, verifyAccAuth}
