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
import {updateQuery} from "pgcrudify"
import crypto from "crypto"
import {mailSender} from "../utils/MailManager.js"
import {authEmailContent} from "../utils/OtpMessage.js"
import resePassFunc from "../utils/ResetPassManager.js"

const userLocalRegister = asyncHandler(async (req, res) => {
    //make sure user is not logged in
    const availableTokens = req.cookies?.accessToken || req.cookies?.refreshToken;
    if(availableTokens) throw new ApiError(400, "logout to continue")
   
    //make sure all requred datas are available and proper
    const requiredFields =[
        "name", 
        "email", 
        "phone", 
        "gender", 
        "birth_date",
        "password"
    ];

    const verifyBody = await StrictBodyVerify(req.body, requiredFields, req.file);
    const {name, email, phone, gender, birth_date, password} = req.body;

    //access image from req.file
    const user_image = req.file?.path;
    
    //make sure username and email doesent exist in db
    const checkUserExist = await db.query(`SELECT * FROM check_user_exist($1,$2)`, [email, phone])
    const existData = checkUserExist.rows;
    let existArray=[]
    for(let val of existData){
        for(let obj in val){
            if(val[obj] == email){
                existArray.push(obj)
            }else if (val[obj] == phone){
                existArray.push(obj)
            }
        }
    }

    //check if user already exist
    if(existArray.length === 1){
        throw new ApiError(400, `${existArray[0]} already in use`);
        if(user_image) fs.unlinkSync(user_image)
    }else if (existArray.length > 1){
        throw new ApiError(400, `${existArray[0]} and ${existArray[1]} already in use`)
        if(user_image) fs.unlinkSync(user_image)
    }
    
    //upload image on cloudinary
    const upload_user_image = await uploadOnCloudinary(user_image);
    const cloudinary_image_path = upload_user_image?.url || null;
    
    //hasing the password
    const hashedPass = await hashPass(password);

    //getting current date and time
    const currDate = new Date().toISOString();
    
    //save user details into db
    const addUser = await db.query(
        `
        INSERT INTO users (
          name, 
          email, 
          phone_number, 
          user_image, 
          gender, 
          birth_date,
          password_hash, 
          created_at
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8
        ) RETURNING user_id, name, email, phone_number, user_image
        `, [
          name, 
          email, 
          phone, 
          cloudinary_image_path, 
          gender, 
          birth_date,
          hashedPass,
          currDate
      ]);
      if(addUser.rowCount == 0) throw new ApiError(400, "something went wrong");

      const user_id = addUser.rows[0].user_id;
      
      //generate accessToken and refreshToken
      const accessTokenData = addUser.rows[0]
      const random_refresh_id = crypto.randomBytes(15).toString('base64url').slice(0, 10);
      
      const refreshTokenData = {
        id:accessTokenData.user_id,
        unique_id: random_refresh_id
      }
      
      const tokens = await createToken(accessTokenData, refreshTokenData);
      if(!tokens) throw new ApiError(400, "something went wrong");

      const accessToken = tokens.accessToken;
      const refreshToken = tokens.refreshToken;

      //save refreshToken in db
        const saveRefreshToken = await db.query( `
        UPDATE users SET refresh_token = $1 WHERE  user_id = $2 `,
         [refreshToken, user_id]);
         if(saveRefreshToken.rowCount === 0) throw new ApiError(400, "somethinh went wrong");

         return res
         .status(200)
         .cookie("accessToken", accessToken, options)
         .cookie("refreshToken", refreshToken, options)
         .json(new ApiResponse(200, {accessToken, refreshToken}, "user registered successFully"))
});

const userOtpAuth = asyncHandler(async(req, res)=>{
    //make sure req.body is fine
    const allowedFields = ["email", "user_otp", "method"];
    for(let val in req.body){
        if(!allowedFields.includes(val)) throw new ApiError(400, `Unidentified field ${val}`);
        if(String(req.body[val]).trim() === "") throw new ApiError(400, "null fields not allowed")
     }

     const {email, user_otp, method} = req.body;

     if(method !== "verify" && method !== "generate"){
        throw new ApiError(400, `only two method generate and verify are accepted`)
    }

     //regex to check email
     function isValidEmail(email) {
        const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        return regex.test(email);
      }

      const checkMail = isValidEmail(email);
      if(!checkMail) throw new ApiError(400, "invalid email");

      //if only email provided send otp
      if(method === "generate"){

        //make sure user has not provided otp
        if(user_otp) throw new ApiError(400, "dont provide field otp to generate new one")

       // make sure previous otp is expired
        const getPreviousOtp = await db.query(
            `SELECT expiry_at FROM user_otp WHERE email=$1`,[email]
        )

        if(getPreviousOtp.rowCount === 1){
            const curr_local_date = new Date();
             
        const otp_expiry = new Date(getPreviousOtp.rows[0].expiry_at);
           
       //make sure otp is not expired
       if(new Date(curr_local_date) < otp_expiry) throw new ApiError(400, "previous otp not yet expired wait untill it expires")
        
         const deletePreviousOtp = await db.query(
            `DELETE FROM user_otp WHERE email=$1`,[email]
         );

        if(deletePreviousOtp.rowCount === 0) throw new ApiError(400, "something went wrong")
        }

        //generate otp
         const otp = crypto.randomInt(10000, 100000);
         
         //get time and date 
           const currDate = new Date().toISOString();
           const expiryDate = new Date(Date.now() + 3 * 60000).toISOString(); // adds 3 minutes
        
         //save details into db
         const hashed_otp = await hashOtp(String(otp))
      
         const saveAuthDetails = await db.query(
            `INSERT INTO user_otp (email, otp, created_at, expiry_at) VALUES ($1, $2, $3, $4)`,[email, hashed_otp, currDate, expiryDate]
         );

         if(saveAuthDetails.rowCount === 0) throw new ApiError(400, "something went wrong");

         //send otp to user email
         let emailSubject = 'Your Otp from open-bike-se'
         
         const emailText = authEmailContent(otp)

         const sendOtpEmail = await mailSender(email, emailSubject, emailText);
         if(!sendOtpEmail) throw new ApiError(400, "soemthing went wrong");

         return res
         .status(200)
         .json(new ApiResponse(200, {}, "Otp sent successFully"))
      }

      if(method === "verify"){
        const getStoredOtp = await db.query(
            `SELECT otp, expiry_at FROM user_otp WHERE email = $1`, [email]
        )
        if(getStoredOtp.rowCount === 0) throw new ApiError(400, "Otp not found please generate one to continue")
            
       const otp_expiry = new Date(getStoredOtp.rows[0].expiry_at);
       const stored_otp = getStoredOtp.rows[0].otp;
       
       const curr_local_date = new Date().toISOString();
      
       //make sure otp is not expired
       if(new Date(curr_local_date) > otp_expiry){
        const deleteOtp = await db.query(
            `DELETE from user_otp WHERE email =$1`,[email]
        )

        if(deleteOtp.rowCount === 0) throw new ApiError(400, "something went wrong");
        throw new ApiError(400, "otp expired");
       }

       //make sure otp is coorect
       const otpSame = await compareOtp(String(user_otp), stored_otp);
       if(!otpSame) throw new ApiError(400, "Wrong otp");
       
       const deleteOtp = await db.query(
        `DELETE FROM user_otp WHERE email =$1`,[email]
       )

       if(deleteOtp.rowCount === 0) throw new ApiError(400, "something went wrong");
       
       return res
       .status(200)
       .json(new ApiResponse(200, {}, "Authentication successFull"))

      }
});

const resetPassAuth = asyncHandler(async(req, res)=>{
    const allowedFields =["email", "phone_number", "method", "otp"];
    
    const bodyKeys = Object.keys(req.body);
    if(bodyKeys.length > 2) throw new ApiError(400, "only one filed allowed email, phone")
    
    for(let val in req.body){
        if(allowedFields.includes(val) === false) throw new ApiError(400, `Unknown field ${val}`);
        if(String(req.body[val]).trim() === "") throw new ApiError(400, `received null value at ${val}`)
    }

    const {email, phone_number, method, otp} = req.body;
    let cookieOtpToken = null;

    if(method === "verify" && !otp) throw new ApiError(400, "please provide otp to continue")

    if(bodyKeys.length === 1 && method === "generate"){
        if(!req.user) throw new ApiError(400, `Please credential or login to continue`);
        const user_id = req.user.user_id;
        const cookie_email = req.user.email;

        if(!user_id) throw new ApiError(400, 'something went wrong');

        //get users email from table
        const get_user_data = await db.query(
            `SELECT 
            u.email,
            r.expiry_at 
            FROM users u
            LEFT JOIN reset_pass_otp r 
            ON u.user_id = r.user_id
            `
        );
      
        if(get_user_data.rowCount === 0) throw new ApiError(400, 'something went wrong');

        const stored_email = get_user_data.rows[0].email;
        const stored_expiry = get_user_data.rows[0].expiry_at;

        const resetManager = await resePassFunc(user_id, stored_email, stored_expiry)
        cookieOtpToken = resetManager
    }

    if(bodyKeys.length === 2 && method === "generate"){
        //make sure email or phone is provided
        if(!email && !phone_number) throw new ApiError(400, "please provide email or phone");
        const availObj ={}
        if(email) availObj.email = email;
        if(phone_number) availObj.phone_number = phone_number;

        let avail_key = null;
        let avail_val = null;
        
        for(let val in availObj){
           avail_key = val;
           avail_val = availObj[val]
        }

        //get users email from table
        const get_user_data = await db.query(
            `SELECT
            u.user_id,
            u.email,
            r.expiry_at 
            FROM users u
            LEFT JOIN reset_pass_otp r
            ON u.user_id = r.user_id
            WHERE u.${avail_key}= $1
            `,[avail_val]
        );

        if(get_user_data.rowCount === 0) throw new ApiError(400, "something went wrong")

        const stored_user_id = get_user_data.rows[0].user_id;
        const stored_email = get_user_data.rows[0].email;
        const stored_expiry = get_user_data.rows[0].expiry_at;

        const resetManager = await resePassFunc(stored_user_id, stored_email, stored_expiry)
        cookieOtpToken = resetManager
    }

    if(bodyKeys.length === 2 && otp && method === "verify"){
        if(!req.cookies.otpToken) throw new ApiError(400, "Unauthorized access");
        const otpToken = req.cookies.otpToken;
        let tokenData =null;
        try{
            const decryptedToken = await jwt.verify(otpToken, process.env.OTP_TOKEN_SECRET);
            tokenData = decryptedToken;
        }catch(error){
            res.clearCookie("otpToken");
            throw new ApiError(400, "Unauthorized access")
        }
       const user_id = tokenData.user_id;
       const unique_id = tokenData.unique_id;
       const user_otp = otp;

       if(!user_id || !unique_id || !user_otp) throw new ApiError(400, "unauthorized access");

       //comapry otp and unique_id make sure otp is not expired;
       const getOtpData = await db.query(
        `SELECT 
        expiry_at,
        otp,
        status
        FROM reset_pass_otp
        WHERE user_id = $1 AND unique_id = $2`,[user_id, unique_id]
       );

       if(getOtpData.rowCount === 0) throw new ApiError(400, "something went wrong");
       if(getOtpData.rows[0].status === "used") throw new ApiError(400, "unauthorized access")

       const saved_expiry = getOtpData.rows[0].expiry_at;
       const saved_otp = getOtpData.rows[0].otp;

       //make sure otp is not expired
       const curr_date = new Date().toISOString();
       if(new Date(curr_date) > new Date(saved_expiry)) throw new ApiError(400, "otp expired please generate a new one to continue")
       
       const otpSame = await compareOtp(String(otp), saved_otp);
       if(!otpSame) throw new ApiError(400, "wrong otp");

       //useBy time for cookie
       const useBy_date = new Date(Date.now() + 3 * 60000).toISOString();

       //update the otp status to used
       const updateStatus = await db.query(
        `UPDATE
        reset_pass_otp
        SET status = $1, use_by = $2 WHERE user_id = $3`,['used', useBy_date, user_id]
       );

       if(updateStatus.rowCount === 0) throw new ApiError(400,"something went wrong");

       const newTokenData ={
        user_id:tokenData.user_id,
        unique_id:tokenData.unique_id,
        status:"used"
       }
     
       //create new token 
       const resetRouteToken = await resetPass_accesToken(newTokenData);
       if(!resetRouteToken) throw new ApiError(400, "something went wrong");

       return res
       .status(200)
       .clearCookie("otpToken")
       .cookie("restPassToken", resetRouteToken, options)
       .json(new ApiResponse(200, {}, "otp verification successFull"))
    }

    return res
    .status(200)
    .cookie("otpToken", cookieOtpToken, options)
    .json(new ApiResponse(200, {}, "otp sent successFully"))
});

const googleRegister = asyncHandler(async(req, res)=>{
    console.log("received login request")
});

const user_login = asyncHandler(async(req, res)=>{
     //make sure user is not logged in
     const availableTokens = req.cookies?.accessToken || req.cookies?.refreshToken;
     if(availableTokens) throw new ApiError(400, "logout to continue")
    
    //make sure all required datas are available
    const bodyKeys = Object.keys(req.body);
    
    if(bodyKeys[0] !== "email" && bodyKeys[0] !== "phone"){
        throw new ApiError(400, `email or phone is required as first data`)
    }

    if(bodyKeys[1] !== "password"){
        throw new ApiError(400, "password is required as second data")
    }

    //make sure only two datas are provided
    if(bodyKeys.length !== 2) throw new ApiError(400, 'two datas are accepted email or phone and password')

    //make sure no null data is provided
    for(let val in req.body){
        if(String(req.body[val]).trim() === ""){
            throw new ApiError(400, `received null data at ${val}`)
        }
    }

    //access data from req.body
    const {email, phone, password} = req.body;

    //if user available verify credentials and login
    let query = `SELECT
       user_id, 
        name, 
        email, 
        phone_number, 
        user_image, 
        password_hash FROM users WHERE `;
    let values =[];

    if(email){
        query += `email=$1`;
        values.push(email)
    }else if(phone){
        query += `phone=$1`;
        values.push(phone)
    }

    //get user details from db
    const loginQuery = await db.query(query, values);
    if(loginQuery.rowCount === 0) throw new ApiError(400, "user not found");

    //extract user infomation
    const user_details = loginQuery.rows[0];
    const saved_password = user_details.password_hash;
    const user_id = user_details.user_id;

    //compare password
    const password_same = await comparePass(password, saved_password);
    if(!password_same) throw new ApiError(400, "Wrong password");

    const access_token_details = {
        user_id:user_details.user_id, 
        name:user_details.name, 
        email:user_details.email, 
        phone_number:user_details.phone_number, 
        user_image:user_details.user_image
    }

    const random_refresh_id = crypto.randomBytes(15).toString('base64url').slice(0, 10);
    const refresh_token_details ={
        user_id:user_details.user_id,
        unique_id: random_refresh_id
    }

    //create new tokens 
    const tokens = await createToken(access_token_details, refresh_token_details);
    const {accessToken, refreshToken} = tokens;
    const curr_date = new Date().toISOString();
   
    //save refreshToken into db and update the updated_at
    const updateDb = await db.query(
        `
        UPDATE users set refresh_token = $1,  
        updated_at= $2 WHERE user_id = $3
        `, [refreshToken, curr_date, user_id]
    )
    if(updateDb.rowCount === 0) throw new ApiError(400, "something went wrong");

    // Clear existing cookies
    Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie))

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(new ApiResponse(200, {accessToken, refreshToken}, "user login successfully"))
});

const user_logout = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(400, "unauthorized access");
    const user_id = req.user.user_id;
    
    //clear all cookies
    Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie))

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "user logout successfull"))
});

const refreshAccessToken = asyncHandler(async(req, res)=>{
    if(!req.cookies) throw new ApiError(400, "unauthorized access");
    const accessToken = req.cookies?.accessToken || null;
    const refreshToken = req.cookies?.refreshToken;
    let token_expired = true;

    //make sure accessToken is expired
    if(accessToken){
        try{
            const verifyTokenExpired = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
            token_expired = false;
        }catch(error){
            if(error.message === "jwt expired"){
               token_expired = true
            }else {
                throw new ApiError(400, error.message)
            }
        }
    }

    if(!token_expired) throw new ApiError(400, "token not yet expired");

    //verify refreshToken 
    const verifyRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const refresh_user_id = verifyRefreshToken.id;
    const refresh_unique_id = verifyRefreshToken.unique_id;

    //get stored refresh token from user
    const getStoredRefreshToken = await db.query(
        `SELECT 
        name,
        email,
        phone_number,
        user_image, 
        refresh_token 
        FROM users WHERE user_id = $1`,[refresh_user_id]
    );

    if(getStoredRefreshToken.rowCount === 0) throw new ApiError(400, "something went wrong");
    const storedRefreshToken = getStoredRefreshToken.rows[0].refresh_token;
    
    //verify stored refreshToken
    const verifyStoredRefreshToken = jwt.verify(storedRefreshToken, process.env.REFRESH_TOKEN_SECRET);
    const stored_refresh_unique_id = verifyStoredRefreshToken.unique_id;

    //make sure unique id of both refreshToken matches
    if(stored_refresh_unique_id !== refresh_unique_id) throw new ApiError(400, "invalid refreshToken");
    
     //get user data to create new accessToken
    const user_data = getStoredRefreshToken.rows[0];
    delete user_data.refresh_token;
    
    const generateAccessToken = await createAccessToken(user_data, process.env.ACCESS_TOKEN_SECRET);
    
    return res
    .status(200)
    .clearCookie("accessToken")
    .cookie("accessToken", generateAccessToken, options)
    .json(new ApiResponse(200, {}, "token updated successfully"))
});

const delete_account = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(400, "unauthorized access")
    
    //make sure password is available in req.body
    for(let val in req.body){
        if(val !== "password") throw new ApiError(400, "password is required");
        if(String(req.body[val]).trim()=== "") throw new ApiError(400, "received null data at password");
    }
    const user_id = req.user.user_id;
    const password = req.body.password;

    //verify password
    const getSavedPass = await db.query(
        `
        SELECT 
        password_hash FROM users 
        WHERE user_id = $1
        `,[user_id]
    );
    if(getSavedPass.rowCount === 0) throw new ApiError(400, "something went wrong")

   const savedPass = getSavedPass.rows[0].password_hash;
   const passwordSame = await comparePass(password, savedPass);
   if(!passwordSame) throw new ApiError(400, "wrong password");
    
    //delete the account
    const deleteAccount = await db.query(
        ` 
        DELETE FROM users 
        WHERE user_id = $1
        `,[user_id]
    )
    if(deleteAccount.rowCount === 0) throw new ApiError(400, "something went wrong");

    Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));
    return res
    .status(200)
    .json(new ApiResponse(200, {}, "user account deleted successfully"))
});

const update_info = asyncHandler(async(req, res)=>{
    //make sure user is verified
    if(!req.user) throw new ApiError(400, "unauthorized access");
    const user_id = req.user.user_id;

    //old user data 
    let user_data = req.user;
    let name_updated = false;
    
    //make sure req.body id fine
    const allowedFields = ["name", "gender", "birth_date"];
    for(let val in req.body){
        if(allowedFields.includes(val) === false) throw new ApiError(400, `Unidentified field ${val}`);
        if(String(req.body[val]).trim() === "") throw new ApiError(400, `null data received at field ${val}`)
        
        if(val === "name"){
            user_data.name=req.body.name;
            name_updated =true
        }
    }

    //add updated at timeStamp
    const currDate = new Date().toISOString()
    req.body.updated_at = currDate;

    
    //update the data
    const updateData = await updateQuery(db, "users", req.body, {user_id});

    //if name updated accessToken
    if(name_updated){
        const tokens = await createAccessToken(user_data);
        
        return res
        .status(200)
        .clearCookie("accessToken")
        .cookie("accessToken", tokens, options)
        .json(new ApiResponse(200, req.body, "updated information successfully"));
    }

    return res
    .status(200)
    .json(new ApiResponse(200, req.body, "updated information successfully"))
});

const update_credential = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(400, "unauthorized access");

    //make sure req.body is fine
    const allowedFields = ["email", "phone_number", "password"];
    for(let val in req.body){
        if(allowedFields.includes(val) === false) throw new ApiError(400, `Unidentified field ${val}`);
        if(String(req.body[val]).trim() === "") throw new ApiError(400, `null data received at field ${val}`);

        if(val === "email"){
            req.user.email = req.body.email
        }

        if(val === "phone"){
            req.user.phone = req.body.phone;
        }
    }
    if(!req.body.password) throw new ApiError(400, "password is required")

    const user_id = req.user.user_id;
    const password = req.body.password;

    //get the saved password of user
    const getPass = await db.query(
        `SELECT 
        password_hash FROM users WHERE user_id =$1`,[user_id]
    )

    if(getPass.rowCount === 0) throw new ApiError(400, "somethin went wrong");

    //make sure password is correct
    const savedPassword = getPass.rows[0].password_hash;
    const passwordSame = await comparePass(password, savedPassword)
    if(!passwordSame) throw new ApiError(400, "wrong password")

    //delete password from req.body
    delete req.body.password;

    //add the updated at timeStamp
    const curr_date = new Date().toISOString();
    req.body.updated_at = curr_date

    // update the data in table 
    const updateInfo = await updateQuery(db, "users", req.body, {user_id})
    if(updateInfo.rowCount === 0) throw new ApiError(400, "something went wrong")
    const accessToken = await createAccessToken(req.user);
    
    return res
    .status(200)
    .clearCookie("accessToken")
    .cookie("accessToken", accessToken, options)
    .json(new ApiResponse(200, req.body, "updated data successFully"))
});

const update_user_image = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(400, "unauthorized access");

    for(let val in req.body){
        if(val !== "user_image") throw new ApiError(400, "please provide user_image");
        if(String(req.body[val]).trim() === "") throw new ApiError(400, "null data received at user_image")
    }

    const user_id = req.user.user_id;
    const existing_image = req.user?.user_image;
    const user_image = req.file?.path || req.body.user_image;
    let updated_image = null;

    // // //if user_image set to null
    if(user_image === "null"){
        if(existing_image === null || existing_image === "null") throw new ApiError(400, "Image alredy set to null")
        // // delete image from cloudinary
        const deleteImageCloudinary = await deleteFromCloudinary(existing_image);
        if(!deleteImageCloudinary) throw new ApiError(400, "something went wrong")
        
        //add updated_at time stamp
        const curr_date = new Date().toISOString();

        const updateImage = await db.query(
        `UPDATE users SET 
         user_image = null, updated_at = $1 WHERE user_id= $2`,[curr_date, user_id]);

         if(updateImage.rowCount === 0) throw new ApiError(400, "something went wrong")
         req.user.user_image = null;
         updated_image = null;
    }

    // //if user provided new image 
    if(user_image !== "null"){
        //upload image on cloudinary
        const uploadImageCloudinary = await uploadOnCloudinary(user_image);
        const uploadedImageUrl = uploadImageCloudinary.url;
        
        //add updated_at time stamp
        const curr_date = new Date().toISOString();

        //update the data in table
        const updateImage = await db.query(
            `UPDATE users SET user_image = $1, updated_at =$2 WHERE user_id = $3`,[uploadedImageUrl, curr_date, user_id]
        );
        if(updateImage.rowCount === 0) throw new ApiError(400, "something went wrong");
        req.user.user_image = uploadedImageUrl;
        updated_image = uploadedImageUrl;
    }

    const accessToken = await createAccessToken(req.user);
    
    return res
    .status(200)
    .clearCookie("accessToken")
    .cookie("accessToken", accessToken, options)
    .json(new ApiResponse(200, {user_image:updated_image}, "successfully updated image"))
});

const reset_pass = asyncHandler(async(req, res)=>{
    if(!req.cookies.restPassToken) throw new ApiError(400, "unauthorized access");

    const bodyKeys = Object.keys(req.body)
    if(bodyKeys.length !== 1) throw new ApiError(400, "Please new_password");
    if(bodyKeys[0] !== "new_password") throw new ApiError(400, "unidetified field")
    
    for(let val in req.body){
        if(String(req.body[val]).trim() === "") throw new ApiError(400, "null fields not allowed")
    }

    //verify reset pass token
    const verifyToken = await jwt.verify(req.cookies.restPassToken, process.env.RESET_PASS_TOKEN_SECRET);
    
    const {user_id, unique_id, status} = verifyToken;
    const {new_password} = req.body;

    if(!user_id || !unique_id || !status) throw new ApiError(400, "something went wrong")
   
    //verify the token data 
    const verifyTokenData = await db.query(
        `SELECT 
        use_by,
        status 
        FROM reset_pass_otp
        WHERE user_id =$1 AND unique_id =$2 AND status =$3`,[user_id, unique_id, status]
    );

    if(verifyTokenData.rowCount === 0) throw new ApiError(400, "something went wrong");

    //make sure access is not expired
    const curr_date = new Date().toISOString();
    const stored_use_by = verifyTokenData.rows[0].use_by;
    
    if(new Date(curr_date) > new Date(stored_use_by)) throw new ApiError(400, "Route Validity exprired");
    
    //hash the password
    const hashed_password = await hashPass(new_password);
  
    //update password and delete the otp data
    const resetQuery = await db.query(
        `WITH update_pass as (
        UPDATE users 
        SET password_hash=$1 
        WHERE user_id = $2
        )
        DELETE FROM 
        reset_pass_otp 
        WHERE user_id = $2`,[hashed_password, user_id]
    )

    if(resetQuery.rowCount === 0) throw new ApiError(400, "something went wrong");

    return res
    .status(200)
    .clearCookie("restPassToken")
    .json(new ApiResponse(200, {}, "Password updated successFully"))
});

export {
    userLocalRegister,
    googleRegister,
    userOtpAuth,
    user_login, 
    user_logout,
    refreshAccessToken,   
    delete_account,
    update_info,
    update_credential,
    update_user_image,
    resetPassAuth,
    reset_pass
}
