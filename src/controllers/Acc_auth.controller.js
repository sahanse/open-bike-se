import {asyncHandler} from "../utils/AsyncHandler.js"
import {ApiResponse} from "../utils/ApiResponse.js"
import {ApiError} from "../utils/ApiError.js"
import db from "../db/index.js"
import jwt from "jsonwebtoken"
import {session_options} from "../utils/Constants.js"

import {otpManager, verifyManager} from "../utils/accAuth.manager.js"

const generateOtp = asyncHandler(async(req, res)=>{
    const requiredFields = ["email", "requester", "type"];
    const bodyKeys = Object.keys(req.body);
    if(bodyKeys.length < 1) throw new ApiError(400, "Please provide all data required");
    
    for(let val in req.body){
        if(!requiredFields.includes(val)) throw new ApiError(400, `Make sure all provided fields are correct`);
        if(String(req.body[val]).trim() === "") throw new ApiError(400, `Null value received at ${val}`)
     }

    let {email, requester, type} = req.body;

    if(!req.auth_data){
        if(requester !== "user" && requester !== "rider") throw new ApiError(400, `requester should be either 'rider' or 'user'`);
    }
    let table = requester === "user" ? "users" : "riders";

    // if type 'register' check wethr user alredy exist with email"
    if(type === "register" ){
        const email_exist_query = await db.query(
            `SELECT email 
            FROM ${table}
            WHERE email =$1`,[email]
        );

        if(email_exist_query.rowCount ===1) throw new ApiError(400, "Email alredy in use");
    };

    //if type 'login' make sure user is alreday exist
    if(type === "login"){
        const email_exist_query = await db.query(
            `SELECT email 
            FROM ${table}
            WHERE email =$1`,[email]
        );

        if(email_exist_query.rowCount ===0) throw new ApiError(400, "User not found");
    };

    if(type === "reset-pass"){
        if(!email){
            if(!req.auth_data) throw new ApiError(400, "Unauthorized access");
            email = req.auth_data.email;
            requester = req.auth_data.requester;
            table = req.auth_data. requester_table;
        }
        const email_exist_query = await db.query(
            `SELECT email 
            FROM ${table}
            WHERE email =$1`,[email]
        );

        if(email_exist_query.rowCount ===0) throw new ApiError(400, "User not found");
    }

    const authenticate_request = await otpManager(email, requester, type)
    // if(!authenticate_request) throw new ApiError(400, "something went wrong");
    return res
    .status(200)
    .cookie("auth_token", authenticate_request, session_options)
    .json(new ApiResponse(200, {auth_token:authenticate_request}, "Otp sent successFully"))
});

const verifyOtp = asyncHandler(async(req, res)=>{
    if(!req.cookies?.auth_token) throw new ApiError(400, "Unauthorized access");
    const bodyKeys = Object.keys(req.body);
    const requiredFields = ["otp", "type"]
    if(bodyKeys.length < 2 ) throw new ApiError(400, "Provide all required fields only")

    for(let val in req.body){
        if(!requiredFields.includes(val)) throw new ApiError(400, `Make sure all provided fields are correct`);
        if(String(req.body[val]).trim() === "") throw new ApiError(400, `Null value received at ${val}`)
     }

   const {otp, type} = req.body;

    if(type === "login"){
        //make sure token is not expired
        const verifyToken = await jwt.verify(req.cookies.auth_token, process.env.AUTH_TOKEN_SECRET);
        
        const token_random_id = verifyToken.random_id;
        const token_email = verifyToken.email;
        const token_type = verifyToken.type;
        const requester = verifyToken.requester;

        if(token_type !== "login") throw new ApiError(400, "Unauthorizeed request type");
        
        const verify_otp = await verifyManager("login", token_email, otp, token_random_id, requester);
        if(!verify_otp) throw new ApiError(400, "something went wrong")

        Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));

        return res
        .status(200)
        .cookie("login_token", verify_otp, session_options)
        .json(new ApiResponse(200,{login_token:verify_otp}, "verification successFull"))
    };

    if(type === "register"){
      
        //make sure token is not expired
        const verifyToken = await jwt.verify(req.cookies.auth_token, process.env.AUTH_TOKEN_SECRET);
        
        const token_random_id = verifyToken.random_id;
        const token_email = verifyToken.email;
        const token_type = verifyToken.type;
        const requester = verifyToken.requester;

        if(token_type !== "register") throw new ApiError(400, "Unauthorizeed request type");
        
        const verify_otp = await verifyManager("register", token_email, otp, token_random_id, requester);
        if(!verify_otp) throw new ApiError(400, "something went wrong")

        Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));

        return res
        .status(200)
        .cookie("reg_token", verify_otp, session_options)
        .json(new ApiResponse(200, {reg_token:verify_otp}, "verification successFull"))
    };

    if(type === "reset-pass"){
          //make sure token is not expired
          const verifyToken = await jwt.verify(req.cookies.auth_token, process.env.AUTH_TOKEN_SECRET);
        
          const token_random_id = verifyToken.random_id;
          const token_email = verifyToken.email;
          const token_type = verifyToken.type;
          const requester = verifyToken.requester;
  
          if(token_type !== "reset-pass") throw new ApiError(400, "Unauthorizeed request type");
          
          const verify_otp = await verifyManager("reset-pass", token_email, otp, token_random_id, requester);
          if(!verify_otp) throw new ApiError(400, "something went wrong 1")
   
          return res
          .status(200)
          .clearCookie("auth_token")
          .cookie("reset_pass_token", verify_otp, session_options)
          .json(new ApiResponse(200,{reset_pass_token:verify_otp}, "verification successFull"))
    }
});

export {
    generateOtp,
    verifyOtp
}


