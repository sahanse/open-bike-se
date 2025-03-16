import {asyncHandler} from "../utils/AsyncHandler.js"
import {ApiResponse} from "../utils/ApiResponse.js"
import {ApiError} from "../utils/ApiError.js"
import {StrictBodyVerify} from "../utils/ReqBodyVerify.js"
import db from "../db/index.js"
import {hashPass, comparePass, hashOtp, compareOtp} from "../utils/Bcrypt.js"
import fs, { stat } from "fs"
import jwt from "jsonwebtoken"
import {uploadOnCloudinary, deleteFromCloudinary} from "../utils/Cloudinary.js"
import {createToken, createAccessToken, resetPass_accesToken} from "../utils/JwtManager.js"
import {options} from "../utils/Constants.js"
import crypto from "crypto"
import {mailSender} from "../utils/MailManager.js"
import {authEmailContent} from "../utils/OtpMessage.js"
import resePassFunc from "../utils/ResetPassManager.js"
import {updateQuery} from "pgcrudify"

const riderRegister = asyncHandler(async(req, res)=>{

    if(req.cookies?.riderAccessToken || req.cookies?.riderRefreshToken) throw new ApiError(400, "logout to continue")

    let riderImage = req.file?.path;
    if(!riderImage) throw new ApiError(400, "rider_image is required")

    const bodyKeys = Object.keys(req.body);
    const requiredFields = ["name", "email", "phone", "birth_date", "gender", "license_no", "password"];
    
    for(let val of requiredFields){
        if(!bodyKeys.includes(val)){
        fs.unlinkSync(riderImage)
        throw new ApiError(400, `${val} field is required`)
        }
        if(String(req.body[val]).trim() === ""){
          fs.unlinkSync(riderImage)
          throw new ApiError(400, `Received null data in ${val}`)
        }
    }
    
    const riderData = req.body;

    //if riderImage available upload on cloudinary
    if(riderImage){
        const uploadImage = await uploadOnCloudinary(riderImage);
        riderImage = uploadImage.url
    }

    const curr_date = new Date().toISOString();

    const {name, email, phone, birth_date, gender, license_no, password} = req.body;
    const status = 'not available'
    const random_refresh_id = crypto.randomBytes(15).toString('base64url').slice(0, 10);
    const refresh_token_expiry = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString();

    const savedRefreshTokenData = {
        refresh_id:random_refresh_id,
        expiry:refresh_token_expiry
    }

    let rider_id = null;
    const hashed_password = await hashPass(password);

    try{
        const createRider = await db.query(
            `INSERT INTO riders 
            (name,
            email,
            phone,
            birth_date,
            rider_image,
            gender,
            license_no,
            created_at,
            status,
            refresh_token,
            hashed_password) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) 
            RETURNING rider_id, rider_image`,[
                name, 
                email,
                phone,
                birth_date,
                riderImage,
                gender,
                license_no,
                curr_date,
                status,
                savedRefreshTokenData,
                hashed_password
            ]
        )
        if(createRider.rowCount === 0) throw new ApiError(400, "something went wrong");
        rider_id = createRider.rows[0].rider_id;
    }catch(error){
        if(error.message === 'duplicate key value violates unique constraint "riders_phone_key"'){
            const deleteImage = await deleteFromCloudinary(riderImage)
            throw new ApiError(400, "phone number already in use");
        }else if(error.message === 'duplicate key value violates unique constraint "riders_email_key"'){
            const deleteImage = await deleteFromCloudinary(riderImage)
            throw new ApiError(400, "email already in use")
        }else if (error.message === `duplicate key value violates unique constraint "riders_license_no_key"`){
            const deleteImage = await deleteFromCloudinary(riderImage)
            throw new ApiError(400, "license no alreay in use")
        }
        const deleteImage = await deleteFromCloudinary(riderImage)
        throw new ApiError(400, "something went wrong")
    }  

    const access_token_data = {
        rider_id,
        name,
        email,
        phone,
        rider_image:riderImage
    }

    const refresh_token_data ={
        rider_id,
        random_refresh_id
    }

    //create tokens
    const tokens = await createToken(access_token_data, refresh_token_data);
    const {accessToken, refreshToken} = tokens;

    return res
    .status(200)
    .cookie("riderAccessToken", accessToken, options)
    .cookie("riderRefreshToken", refreshToken, options)
    .json(new ApiResponse(200,{riderImage},"user_registered successfully"))

});

const riderLogin = asyncHandler(async(req, res)=>{

    if(req.cookies?.riderAccessToken || req.cookies?.riderRefreshToken) throw new ApiError(400, "logout to continue")
    
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
        riders 
        set refresh_token = $1
        WHERE ${bodyKeys[0]} = $2 
        RETURNING
        rider_id,
        name,
        email,
        phone,
        rider_image,
        hashed_password 
        `,[savedRefreshTokenData, bodyVal[0]]
    );

    //make sure user exists
    if(user_db_query.rowCount === 0) throw new ApiError(400, `User not found`);
    
    const {rider_id, name, email, phone, rider_image, hashed_password} = user_db_query.rows[0]
    
    //compare password
    const same_pass = await comparePass(user_password, hashed_password);

    if(!same_pass) throw new ApiError(400, "Wrong password");

    //create new Tokens
    const access_token_data = {
        rider_id,
        name,
        email,
        phone,
        rider_image
    }

    const refresh_token_data ={
        rider_id,
        random_refresh_id
    }

    //create tokens
    const {accessToken, refreshToken} = await createToken(access_token_data, refresh_token_data);

    //clear all existing cookies
    Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));

    return res
    .status(200)
    .cookie("riderAccessToken", accessToken, options)
    .cookie("riderRefreshToken", refreshToken, options)
    .json(new ApiResponse(200, {riderAccessToken:accessToken, riderRefreshToken:refreshToken}))
});

const riderLogout = asyncHandler(async(req, res)=>{
    if(!req.rider) throw new ApiError(400, "something went wrong");

    const rider_id = req.rider.rider_id;
    
    //delete refeeshToken from riderTable
    const update_token_db = await db.query(
        `UPDATE riders 
        SET refresh_token = $1 
        WHERE rider_id =$2`,[null, rider_id]
    );

    if(update_token_db.rowCount === 0) throw new ApiError(400, "something went wrong");

    //delete cookies
    Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "logout successfull"))
});

const riderAccDelete = asyncHandler(async(req, res)=>{
    if(!req.rider) throw new ApiError(400, "Unauthorized access");

    for(let val in req.body){
        if(val !== "password") throw new ApiError(400, `Unidentified field ${val} Only field password is required`);
        if(String(req.body[val]).trim() === "") throw new ApiError(400, 'Null value not accepted')
    }

    const rider_id = req.rider.rider_id;

    //get users stored password
    const get_stored_pass = await db.query(
        `SELECT hashed_password
        FROM riders 
        WHERE rider_id = $1`,[rider_id]
    );

    if(get_stored_pass.rowCount === 0) throw new ApiError(400, 'something went wrong');

    const stored_pass = get_stored_pass.rows[0].hashed_password;
    const rider_pass = req.body.password;

    const isPass_same = await comparePass(rider_pass, stored_pass);
    if(!isPass_same) throw new ApiError(400, "Wrong password");

    //delete the account
    const delete_acc_db = await db.query(
        `DELETE from riders 
        WHERE rider_id = $1`,[rider_id]
    );

    if(delete_acc_db.rowCount === 0) throw new ApiError(400, "something went wrong");

    Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));

    return res
    .status(200)
    .json(new ApiResponse(200, {}, 'SuccessFully deleted account'))
});

const refreshAccessToken = asyncHandler(async(req, res)=>{
    const {riderAccessToken, riderRefreshToken} = req.cookies;
    if(!riderRefreshToken) throw new ApiError(400, "Unauthorized access")

    if(riderAccessToken){
        try{
            const verify_access_expired = await jwt.verify(riderAccessToken, process.env.ACCESS_TOKEN_SECRET);
            if(verify_access_expired) throw 'AccessToken still valid'
        }catch(error){
            if(error.message !== "jwt expired") throw new ApiError(400, error)
        }
    }

    //verify refreshToken 
    const verify_refresh_token = await jwt.verify(riderRefreshToken, process.env.REFRESH_TOKEN_SECRET);
    if(!verify_refresh_token) throw new ApiError(400, "something went wrong");

    const unique_refresh_id =  verify_refresh_token.random_refresh_id;
    const refresh_rider_id = verify_refresh_token.rider_id;
    //make sure matched with saved refresh token
    const get_db_refresh_data = await db.query(
        `SELECT
        rider_id,
        name,
        email,
        phone,
        rider_image,
        refresh_token 
        FROM riders 
        WHERE rider_id = $1`,[refresh_rider_id]
    );
    if(get_db_refresh_data.rowCount === 0) throw new ApiError(400, "something went wrong");

    const {rider_id, name, email, phone, rider_image} = get_db_refresh_data.rows[0]

    const {expiry, refresh_id} = get_db_refresh_data.rows[0].refresh_token;
    const curr_date = new Date().toISOString();

    if(new Date(curr_date) > new Date(expiry)) throw new ApiError(400, "RefreshToken expired re-login to continue")

    if(refresh_id !== unique_refresh_id) throw new ApiError(400, "Unauthorized access");

    const access_token_data={
        rider_id,
        name,
        email,
        phone,
        rider_image
    }
    //generate new AcessToken 
    const new_access_token = await createAccessToken(access_token_data);
    
    return res
    .status(200)
    .cookie("riderAccessToken", new_access_token, options)
    .json(new ApiResponse(200, {riderAccessToken:new_access_token}))
});
   
const updateInfo = asyncHandler(async(req, res)=>{
    if(!req.rider) throw new ApiError(400, "Unauthorized access");

    const allowedFields = ["name", "email", "phone", "birth_date", "gender", "license_no","status"];
    const bodyKeys = Object.keys(req.body);
    if(bodyKeys.length === 0) throw new ApiError(400, "Empty object not allowed")

    for(let val in req.body){
        if(!allowedFields.includes(val))throw new ApiError(400, `Unidentified field ${val}`);
        if(String(req.body[val]).trim() === "") throw new ApiError(400, `Null value received at ${val}`);
    }

    const rider_id = req.rider.rider_id;
  
    //update the data in table
    const update_rider_data = await updateQuery(db, "riders", req.body, {rider_id});
    if(update_rider_data.rowCount === 0) throw new ApiError(400, "something went wrong");

    const nameUpdated = null;
    if(bodyKeys.includes("name")){
        const curr_access_data = req.rider;
        curr_access_data.name = req.body.name;
        const new_access_token = await createAccessToken(curr_access_data);
        res.clearCookie("riderAccessToken");
        return res
        .status(200)
        .cookie("riderAccessToken", new_access_token, options)
        .json(new ApiResponse(200, {riderAccessToken:new_access_token}, "data updated successFully"));
    }

    return res
    .status(200)
    .json(new ApiResponse(200, req.body,"data updated successFully"))

});

const updateCreticalInfo = asyncHandler(async(req, res)=>{
    //route for updateing crutial info like email, phone, license_no and password
    if(!req.rider) throw new ApiError(400, "Unauthorized access");
    
    const bodyKeys = Object.keys(req.body);
    if(bodyKeys.length === 0) throw new ApiError(400, 'Empty object not allowed');
    if(!bodyKeys.includes("password")) throw new ApiError(400, "Pasword is required")

    const allowedFields = ["email", "phone", "license_no", "new_password", "password"];

    for(let val in req.body){
       if(!allowedFields.includes(val)) throw new ApiError(400, `Unidentified field ${val}`);
       if(String(req.body[val]).trim() === "") throw new ApiError(400, `Received null data at ${val}`)
    }

    const rider_id = req.rider.rider_id;
    
    //get the riders password
    const get_rider_pass = await db.query(
        `SELECT hashed_password 
        FROM riders
        WHERE rider_id = $1`,[rider_id]
    );

    if(get_rider_pass.rowCount === 0) throw new ApiError(400, "something went wrong");
    const stored_rider_pass = get_rider_pass.rows[0].hashed_password;
    const rider_pass = req.body.password;

    //comapre both password are same
    const is_pass_same = await comparePass(rider_pass, stored_rider_pass);
    if(!is_pass_same) throw new ApiError(400, "Wrong password")
    delete(req.body.password)

    //logic if password update is requested
    if(bodyKeys.includes("new_password")){
        const hash_new_pass = await hashPass(rider_pass);
        delete(req.body.new_password);
        req.body.hashed_password = hash_new_pass;
    }

    //update the data 
    const update_rider_data = await updateQuery(db, "riders", req.body, {rider_id});
    if(update_rider_data.rowCount === 0) throw new ApiError(400, "something went wrong");

    if(bodyKeys.includes("email") || bodyKeys.includes("phone")){
        if(bodyKeys.includes("email")) req.rider.email = req.body.email;
        if(bodyKeys.includes("phone")) req.rider.phone = req.body.phone;

        const new_access_token = await createAccessToken(req.rider);
        res.clearCookie("riderAccessToken");
        
        return res
        .status(200)
        .cookie("riderAccessToken", new_access_token, options)
        .json(new ApiResponse(200, {riderAccessToken:new_access_token}, "successFully updated data"))
    }

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "data updated successFully"))

});

const updateImage = asyncHandler(async(req, res)=>{
    if(!req.rider) throw new ApiError(400, "Unauthorized access");
    if(!req.file) throw new ApiError(400, "Image cant be null");

    const new_rider_image = req.file.path;
    
    const rider_id = req.rider.rider_id;
    const existing_rider_image = req.rider.rider_image;

    //delete the exsiting rider image from cloudinary
    const delete_existing_image = await deleteFromCloudinary(existing_rider_image);
    if(!delete_existing_image) throw new ApiError(400, "something went wrong");

    //upload new Image on cloudinary
    const upload_image = await uploadOnCloudinary(new_rider_image);
    if(!upload_image) throw new ApiError(400, "something went wrong");

    const new_image_link = upload_image.url;

    //update the image in db
    const update_image = await db.query(
        `UPDATE riders 
        SET rider_image = $1
        WHERE rider_id = $2`,[new_image_link, rider_id]
    );

    if(update_image.rowCount === 0) throw new ApiError(400, "something went wrong");

    req.rider.rider_image = new_image_link;

    //create new AccessToken 
    const new_access_token = await createAccessToken(req.rider);

    return res
    .status(200)
    .cookie("riderAccessToken", new_access_token, options)
    .json(new ApiResponse(200, {rider_image:new_image_link}, "image updated successFully"))
    
});

const resetPass = asyncHandler(async(req, res)=>{
    console.log("received login request")
});

export {
    riderRegister,
    riderLogin,
    riderLogout,
    refreshAccessToken,
    riderAccDelete,
    updateInfo,
    updateCreticalInfo,
    updateImage,
    resetPass
}

