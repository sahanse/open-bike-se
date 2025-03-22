import {asyncHandler} from "../utils/AsyncHandler.js"
import {ApiResponse} from "../utils/ApiResponse.js"
import {ApiError} from "../utils/ApiError.js"
import db from "../db/index.js"
import {hashPass, comparePass,compareOtp} from "../utils/Bcrypt.js"
import fs from "fs"
import jwt from "jsonwebtoken"
import {uploadOnCloudinary, deleteFromCloudinary} from "../utils/Cloudinary.js"
import {createToken, createAccessToken} from "../utils/JwtManager.js"
import {access_options, refres_options} from "../utils/Constants.js"
import {updateQuery} from "pgcrudify"
import crypto from "crypto"
import bcrypt from "bcrypt"

const userRegister = asyncHandler(async(req, res)=>{
    let userImage = req.file?.path || null;
    if(!req.cookies?.reg_token){
        if(userImage) fs.unlinkSync(userImage)
        throw new ApiError(400, "Unauthorized access");
    } 
    const verify_reg_token = await jwt.verify(req.cookies.reg_token, process.env.AUTH_TOKEN_SECRET);

    if(req.cookies?.accessToken || req.cookies?.refreshToken) throw new ApiError(400, "logout to continue")
   
    const bodyKeys = Object.keys(req.body);
    const requiredFields = ["name", "email", "phone", "gender", "birth_date", "password"];
    
    for(let val of requiredFields){
        if(!bodyKeys.includes(val)){
        if(userImage) fs.unlinkSync(userImage)
        throw new ApiError(400, `${val} field is required`)
        }
        if(String(req.body[val]).trim() === ""){
         if(userImage) fs.unlinkSync(userImage)
         throw new ApiError(400, `Received null data in ${val}`)
        }
    }

    const {name, email, phone, gender, birth_date, password} = req.body;

    const cookie_email = verify_reg_token.email;
    const cookie_requester = verify_reg_token.requester;

    if(email !== cookie_email) throw new ApiError(400, "Unauthorzied email");
    if(cookie_requester !== "user") throw new ApiError(400, "Unauthorized requester");

    const cookie_token_id = verify_reg_token.id;
    const cookie_verified_id = verify_reg_token.verify_id;

    //make sure stored verify_id and cookies verify id are same
    const get_verified_data = await db.query(
        `SELECT verified_id 
        from reg_auth 
        WHERE id=$1 AND email =$2`,[cookie_token_id, cookie_email]
    );
  
    if(get_verified_data.rowCount === 0) throw new ApiError(400, "Unauthorized request");
    const stored_verified_id = get_verified_data.rows[0]?.verified_id;
    
    const is_verify_id_same = await bcrypt.compare(String(cookie_verified_id), stored_verified_id)
    if(!is_verify_id_same) throw new ApiError(400, "Unauthorized access");

    //if userImage available upload on cloudinary
    if(userImage){
        const uploadImage = await uploadOnCloudinary(userImage);
        userImage = uploadImage?.url
    }

    const curr_date = new Date().toISOString();

    const random_refresh_id = crypto.randomBytes(15).toString('base64url').slice(0, 10);
    const refresh_token_expiry = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString();

    const savedRefreshTokenData = {
        refresh_id:random_refresh_id,
        expiry:refresh_token_expiry
    }

    let user_id = null;
    const hashed_password = await hashPass(password);

    try{
        const createUser = await db.query(
            `INSERT INTO users 
            (name,
            email,
            phone,
            user_image,
            gender,
            birth_date,
            hashed_password,
            created_at,
            refresh_token) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
            RETURNING user_id, user_image`,[
                name,
                email,
                phone,
                userImage,
                gender,
                birth_date,
                hashed_password,
                curr_date,
                savedRefreshTokenData,
            ]
        )
        if(createUser.rowCount === 0) throw new ApiError(400, "something went wrong");
        user_id = createUser.rows[0].user_id;
    }catch(error){
        if(error.message === 'duplicate key value violates unique constraint "users_phone_number_key"'){
            if(userImage) await deleteFromCloudinary(userImage)
            throw new ApiError(400, "phone number already in use");
        }else if(error.message === 'duplicate key value violates unique constraint "users_email_key"'){
            if(userImage) await deleteFromCloudinary(userImage)
            throw new ApiError(400, "email already in use")
        }
        if(userImage) await deleteFromCloudinary(userImage)
        throw new ApiError(400, error)
    } 

    //delete the verifyToken data from db
    const delete_verify = await db.query(
        `DELETE FROM reg_auth
        WHERE id = $1`,[cookie_token_id]
    );

    if(delete_verify.rowCount === 0) throw new ApiError(400, "something went wrong")

    const access_token_data = {
        requester:"user",
        user_id,
        name,
        email,
        phone,
        user_image:userImage
    }

    const refresh_token_data ={
        requester:"user",
        user_id,
        random_refresh_id
    }

    //create tokens
    const tokens = await createToken(access_token_data, refresh_token_data);
    const {accessToken, refreshToken} = tokens;

    Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));

    return res
    .status(200)
    .cookie("accessToken", accessToken, access_options)
    .cookie("refreshToken", refreshToken, refres_options)
    .json(new ApiResponse(200,{userImage},"user registered successfully"))
});

const googleRegister = asyncHandler(async(req, res)=>{
    console.log("received login request")
});

const userLogin = asyncHandler(async(req, res)=>{

    if(req.cookies?.accessToken || req.cookies?.refreshToken) throw new ApiError(400, "logout to continue")
    
    const bodyKeys = Object.keys(req.body);
    const bodyVal = Object.values(req.body);

    if(bodyKeys.length !== 2) throw new ApiError(400, "please provide all required data");
    
    if(bodyKeys[0] !== "email" && bodyKeys[0] !== "phone") throw new ApiError(400, "please provide email or phone to continue")
    if(bodyKeys[1] !== "password") throw new ApiError(400, "password is required as second field")

    for(let val in req.body){
        if(String(req.body[val]).trim() === "") throw new ApiError(400, `Null data received in ${val}`);
        if(val === "email"){
            const isValid = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(req.body[val]);
            if(!isValid) throw new ApiError(400, "email not valid")
        }
        
        if(val === "phone"){
            if(String(req.body[val]).length !== 10) throw new ApiError(400, 'Invalid phone number')
        }
    }
    const user_password = req.body.password;

    //create a refresh token data to store in db
    const random_refresh_id = crypto.randomBytes(15).toString('base64url').slice(0, 10);
    const refresh_token_expiry = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString();

    const savedRefreshTokenData = {
        refresh_id:random_refresh_id,
        expiry:refresh_token_expiry
    }

    //get users detials from db
    const user_db_query = await db.query(
        `
        UPDATE 
        users
        set refresh_token = $1
        WHERE ${bodyKeys[0]} = $2 
        RETURNING
        user_id,
        name,
        email,
        phone,
        user_image,
        hashed_password 
        `,[savedRefreshTokenData, bodyVal[0]]
    );

    //make sure user exists
    if(user_db_query.rowCount === 0) throw new ApiError(400, `User not found`);
    
    const {user_id, name, email, phone, user_image, hashed_password} = user_db_query.rows[0]
    
    //compare password
    const same_pass = await comparePass(user_password, hashed_password);

    if(!same_pass) throw new ApiError(400, "Wrong password");

    //create new Tokens
    const access_token_data = {
        requester:"user",
        user_id,
        name,
        email,
        phone,
        user_image
    }

    const refresh_token_data ={
        requester:"user",
        user_id,
        random_refresh_id
    }

    //create tokens
    const {accessToken, refreshToken} = await createToken(access_token_data, refresh_token_data);

    //clear all existing cookies
    Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));

    return res
    .status(200)
    .cookie("accessToken", accessToken, access_options)
    .cookie("refreshToken", refreshToken, refres_options)
    .json(new ApiResponse(200, {accessToken:accessToken, refreshToken:refreshToken}))
});

const user_logout = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(400, "something went wrong");

    const user_id = req.user.user_id;
    
    //delete refeeshToken from riderTable
    const update_token_db = await db.query(
        `UPDATE users 
        SET refresh_token = $1 
        WHERE user_id =$2`,[null, user_id]
    );

    if(update_token_db.rowCount === 0) throw new ApiError(400, "something went wrong");

    //delete cookies
    Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "logout successfull"))
});

const refreshAccessToken = asyncHandler(async(req, res)=>{
    const {accessToken, refreshToken} = req.cookies;
    if(!refreshToken) throw new ApiError(400, "Unauthorized access")

    if(accessToken){
        try{
            const verify_access_expired = await jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
            if(verify_access_expired) throw 'AccessToken still valid'
        }catch(error){
            if(error.message !== "jwt expired") throw new ApiError(400, error)
        }
    }

    //verify refreshToken 
    const verify_refresh_token = await jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    if(!verify_refresh_token) throw new ApiError(400, "something went wrong");

    const unique_refresh_id =  verify_refresh_token.random_refresh_id;
    const refresh_user_id = verify_refresh_token.user_id;
   
    //make sure matched with saved refresh token
    const get_db_refresh_data = await db.query(
       `SELECT
        user_id,
        name,
        email,
        phone,
        user_image,
        refresh_token 
        FROM users 
        WHERE user_id = $1`,[refresh_user_id]
    );
    if(get_db_refresh_data.rowCount === 0) throw new ApiError(400, "something went wrong");

    const {user_id, name, email, phone, user_image} = get_db_refresh_data.rows[0]

    const stored_token = JSON.parse(get_db_refresh_data.rows[0].refresh_token)
    const {expiry, refresh_id} = stored_token;
    const curr_date = new Date().toISOString();

    if(new Date(curr_date) > new Date(expiry)) throw new ApiError(400, "RefreshToken expired re-login to continue")

    if(refresh_id !== unique_refresh_id) throw new ApiError(400, "Unauthorized access 1");

    const access_token_data={
        requester:"user",
        user_id,
        name,
        email,
        phone,
        user_image
    }
    //generate new AcessToken 
    const new_access_token = await createAccessToken(access_token_data);
    
    return res
    .status(200)
    .cookie("accessToken", new_access_token, access_options)
    .json(new ApiResponse(200, {accessToken:new_access_token}))
});

const delete_account = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(400, "Unauthorized access");

    for(let val in req.body){
        if(val !== "password") throw new ApiError(400, `Unidentified field ${val} Only field password is required`);
        if(String(req.body[val]).trim() === "") throw new ApiError(400, 'Null value not accepted')
    }

    const user_id = req.user.user_id;

    //get users stored password
    const get_stored_pass = await db.query(
        `SELECT 
        hashed_password
        FROM users 
        WHERE user_id = $1`,[user_id]
    );

    if(get_stored_pass.rowCount === 0) throw new ApiError(400, 'something went wrong');

    const stored_pass = get_stored_pass.rows[0].hashed_password;
    const user_pass = req.body.password;

    const isPass_same = await comparePass(user_pass, stored_pass);
    if(!isPass_same) throw new ApiError(400, "Wrong password");

    //delete the image from cloudinary if exists
    const user_image = req.user.user_image || null;
    if(user_image){
        const delete_image = await deleteFromCloudinary(user_image);
        if(!delete_image) throw new ApiError(400, "something went wrong")
    }

    //delete the account
    const delete_acc_db = await db.query(
        `DELETE from users 
        WHERE user_id = $1`,[user_id]
    );

    if(delete_acc_db.rowCount === 0) throw new ApiError(400, "something went wrong");

    Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));

    return res
    .status(200)
    .json(new ApiResponse(200, {}, 'account deleted successFully'))
});

const update_info = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(400, "Unauthorized access");
    const allowedFields = ["name", "gender", "birth_date"];
    const bodyKeys = Object.keys(req.body);
    if(bodyKeys.length === 0) throw new ApiError(400, "Empty object not allowed")

    for(let val in req.body){
        if(!allowedFields.includes(val))throw new ApiError(400, `Unidentified field ${val}`);
        if(String(req.body[val]).trim() === "") throw new ApiError(400, `Null value received at ${val}`);
    }

    const user_id = req.user.user_id;
  
    //update the data in table
    const update_user_data = await updateQuery(db, "users", req.body, {user_id});
    if(update_user_data.rowCount === 0) throw new ApiError(400, "something went wrong");

    if(bodyKeys.includes("name")){
        const curr_access_data = req.user;
        curr_access_data.name = req.body.name;
        const new_access_token = await createAccessToken(curr_access_data);
        return res
        .status(200)
        .cookie("accessToken", new_access_token, access_options)
        .json(new ApiResponse(200, {accessToken:new_access_token}, "data updated successFully"));
    }

    return res
    .status(200)
    .json(new ApiResponse(200, req.body,"data updated successFully"))

});

const update_credential = asyncHandler(async(req, res)=>{
    //route for updateing crutial info like email, phone and password
    if(!req.user) throw new ApiError(400, "Unauthorized access");
    
    const bodyKeys = Object.keys(req.body);
    if(bodyKeys.length === 0) throw new ApiError(400, 'Empty object not allowed');
    if(!bodyKeys.includes("password")) throw new ApiError(400, "Pasword is required")

    const allowedFields = ["email", "phone", "new_password", "password"];

    for(let val in req.body){
       if(!allowedFields.includes(val)) throw new ApiError(400, `Unidentified field ${val}`);
       if(String(req.body[val]).trim() === "") throw new ApiError(400, `Received null data at ${val}`)
    }

    const user_id = req.user.user_id;
    
    //get the riders password
    const get_user_pass = await db.query(
        `SELECT hashed_password 
        FROM users
        WHERE user_id = $1`,[user_id]
    );

    if(get_user_pass.rowCount === 0) throw new ApiError(400, "something went wrong");
    const stored_user_pass = get_user_pass.rows[0].hashed_password;
    const user_pass = req.body.password;
    const new_pass = req.body.new_password;

    //comapre both password are same
    const is_pass_same = await comparePass(user_pass, stored_user_pass);
    if(!is_pass_same) throw new ApiError(400, "Wrong password")
    delete(req.body.password)

    //logic if password update is requested
    if(bodyKeys.includes("new_password")){
        const hash_new_pass = await hashPass(new_pass);
        delete(req.body.new_password);
        req.body.hashed_password = hash_new_pass;
    }

    //update the data 
    const update_user_data = await updateQuery(db, "users", req.body, {user_id});
    if(update_user_data.rowCount === 0) throw new ApiError(400, "something went wrong");

    if(bodyKeys.includes("email") || bodyKeys.includes("phone")){
        if(bodyKeys.includes("email")) req.user.email = req.body.email;
        if(bodyKeys.includes("phone")) req.user.phone = req.body.phone;

        const new_access_token = await createAccessToken(req.user); 
        return res
        .status(200)
        .cookie("accessToken", new_access_token, access_options)
        .json(new ApiResponse(200, {accessToken:new_access_token}, "successFully updated data"))
    }

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "data updated successFully"))

});

const update_user_image = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(400, "Unauthorized access");
   
    const new_user_image = req.file?.path || null;
    
    const user_id = req.user.user_id;
    const existing_user_image = req.user.user_image;

    //delete the exsiting rider image from cloudinary
    if(existing_user_image !== null){
        const delete_existing_image = await deleteFromCloudinary(existing_user_image);
        if(!delete_existing_image) throw new ApiError(400, "something went wrong");
    }

    let new_image_link = null;
    if(new_user_image !== null){
        //upload new Image on cloudinary
        const upload_image = await uploadOnCloudinary(new_user_image);
        if(!upload_image) throw new ApiError(400, "something went wrong 2");
        new_image_link = upload_image.url
    }
   
    //update the image in db
    const update_image = await db.query(
        `UPDATE users 
        SET user_image = $1
        WHERE user_id = $2`,[new_image_link, user_id]
    );

    if(update_image.rowCount === 0) throw new ApiError(400, "something went wrong 3");

    req.user.user_image = new_image_link;

    //create new AccessToken 
    const new_access_token = await createAccessToken(req.user);

    return res
    .status(200)
    .cookie("accessToken", new_access_token, access_options)
    .json(new ApiResponse(200, {user_image:new_image_link}, "image updated successFully"))
    
});

const reset_pass = asyncHandler(async(req, res)=>{
    const bodyKeys = Object.keys(req.body);
    if(bodyKeys.length !== 1) throw new ApiError(400, "Only one field 'new_password' is required");

    for(let val in req.body){
       if(val !== "new_password") throw new ApiError(400, `Unidentified field ${val}`);
       if(String(req.body[val]).trim() === "") throw new ApiError(400, `Null value received at ${val}`);
    }
    if(!req.cookies.reset_pass_token) throw new ApiError(400, "Unauthorized access");
    const verifyResetToken = await jwt.verify(req.cookies.reset_pass_token, process.env.AUTH_TOKEN_SECRET);

    const {id, email, verify_id, requester} = verifyResetToken;
    const {new_password} = req.body;

    if(requester !== "user") throw new ApiError(400, "Unauthorized access");

    //get stored info of otp
    const stored_auth_info = await db.query(
        `SELECT otp,
        verified_id 
        FROM reset_pass_auth
        WHERE id = $1 AND 
        email = $2 AND 
        status = $3 AND
        requester = $4`,[id, email, 'verified', requester]
    );
    if(stored_auth_info.rowCount === 0) throw new ApiError(400, "something went wrong");

    const stored_otp = stored_auth_info.rows[0].otp;
    const stored_verified_id =stored_auth_info.rows[0].verified_id;
    
    const compare_verified_id = await compareOtp(String(verify_id), String(stored_verified_id));
    if(!compare_verified_id) throw new ApiError(400, "unauthorized access")
    
    //hash the new password and update in db
    const hash_new_pass = await hashPass(new_password);
    
    const stored_new_pass = await db.query(
        `UPDATE users 
        SET hashed_password = $1
        WHERE email = $2`,[hash_new_pass, email]
    );

    if(stored_new_pass.rowCount === 0) throw new ApiError(400, "something went wrong");

    return res
    .status(200)
    .clearCookie("reset_pass_token")
    .json(new ApiResponse(200, {}, "password updated successFully"))
});

export {
    userRegister,
    googleRegister,
    userLogin, 
    user_logout,
    refreshAccessToken,   
    delete_account,
    update_info,
    update_credential,
    update_user_image,
    reset_pass
}
