import db from "../db/index.js"
import crypto from "crypto"
import {authToken} from "./JwtManager.js"
import {hashOtp} from "./Bcrypt.js"
import {ApiError} from "./ApiError.js"
import bcrypt from "bcrypt"
import {mailSender} from "../utils/MailManager.js"

const registerAuth = async(email, requester)=>{
    //generate otp
    const generated_otp = [...crypto.randomFillSync(new Uint8Array(5))].map(n => n % 10).join('');
    
    //hash the otp
    const hashedOtp = await hashOtp(String(generated_otp));
    
    //save otp and data into db
    const otp_expiry = new Date(Date.now() + 2 * 60 * 1000).toISOString();
    const random_otp_id = crypto.randomBytes(15).toString('base64url').slice(0, 10);
    const hash_id = await hashOtp(random_otp_id);
    
    const otp_token_data ={
        otp_expiry,
        random_id:hash_id
    }

    try {
        // Step 1: Check existing OTP (if any)
        const existingOtpCheck = await db.query(
            `SELECT token FROM reg_auth WHERE email = $1`,
            [email]
        );
    
        if (existingOtpCheck.rows.length > 0 && existingOtpCheck.rows[0]?.token) {
            const { otp_expiry } = existingOtpCheck.rows[0].token;
            const now = new Date().toISOString();
    
            if (new Date(now) < new Date(otp_expiry)) {
                throw new ApiError(400, "Previous OTP not yet expired");
            }
        }
    
        // Step 2: Update count only if we're actually sending a new OTP
        await db.query(
            `INSERT INTO auth_request_counts (email, count, created_at)
             VALUES ($1, 1, now())
             ON CONFLICT (email) DO UPDATE
             SET 
                count = CASE 
                    WHEN auth_request_counts.created_at::date = CURRENT_DATE 
                        THEN auth_request_counts.count + 1 
                    ELSE 1 
                END,
                created_at = CASE 
                    WHEN auth_request_counts.created_at::date = CURRENT_DATE 
                        THEN auth_request_counts.created_at 
                    ELSE now() 
                END`,
            [email]
        );
    
        // Step 3: Upsert OTP (insert or update)
        const upsertOtp = await db.query(
            `INSERT INTO reg_auth (email, otp, requester, token, status)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (email) DO UPDATE
             SET otp = $2, requester = $3, token = $4, status = $5`,
            [email, hashedOtp, requester, otp_token_data, 'pending']
        );
    
    } catch (error) {
        if (error.message.includes("max_count")) {
            throw new ApiError(429, "OTP request limit exceeded for today");
        }
        throw new ApiError(400, error.message);
    }
    
    
    // send otp to user
    const email_content = acc_auth_email_content(generated_otp, requester);
    const email_subject = acc_auth_email_subject()
    
    const send_user_otp = await mailSender(email, email_subject, email_content);
    if(!send_user_otp) throw new ApiError(400, "something went wrong");

    //create otp_reg_token
    otp_token_data.random_id = random_otp_id
    otp_token_data.type ="register";
    otp_token_data.email = email;
    otp_token_data.requester = requester;
    const createOtpToken = await authToken(otp_token_data);
    
    return createOtpToken;
};

const loginAuth = async(email, requester)=>{
    //generate otp
    const generated_otp = [...crypto.randomFillSync(new Uint8Array(5))].map(n => n % 10).join('');
    
    //hash the otp
    const hashedOtp = await hashOtp(String(generated_otp));
    
    //save otp and data into db
    const otp_expiry = new Date(Date.now() + 2 * 60 * 1000).toISOString();
    const random_otp_id = crypto.randomBytes(15).toString('base64url').slice(0, 10);
    const hash_id = await hashOtp(random_otp_id);
   
    
    const otp_token_data ={
        otp_expiry,
        random_id:hash_id
    }

    try {
        // Step 1: Check existing OTP (if any)
        const existingOtpCheck = await db.query(
            `SELECT 
            token 
            FROM 
            login_auth 
            WHERE email = $1`,
            [email]
        );
    
        if (existingOtpCheck.rows.length > 0 && existingOtpCheck.rows[0]?.token) {
            const { otp_expiry } = existingOtpCheck.rows[0].token;
            const now = new Date().toISOString();
    
            if (new Date(now) < new Date(otp_expiry)) {
                throw new ApiError(400, "Previous OTP not yet expired");
            }
        }
    
        // Step 2: Update count only if we're actually sending a new OTP
        await db.query(
            `INSERT INTO auth_request_counts 
            (email, count, created_at)
             VALUES ($1, 1, now())
             ON CONFLICT (email) DO UPDATE
             SET 
                count = CASE 
                    WHEN auth_request_counts.created_at::date = CURRENT_DATE 
                        THEN auth_request_counts.count + 1 
                    ELSE 1 
                END,
                created_at = CASE 
                    WHEN auth_request_counts.created_at::date = CURRENT_DATE 
                        THEN auth_request_counts.created_at 
                    ELSE now() 
                END`,
            [email]
        );
    
        // Step 3: Upsert OTP (insert or update)
        const upsertOtp = await db.query(
            `INSERT INTO login_auth 
            (email, otp, requester, token, status)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (email) DO UPDATE
             SET otp = $2, requester = $3, token = $4, status = $5`,
            [email, hashedOtp, requester, otp_token_data, 'pending']
        );
    
    } catch (error) {
        if (error.message.includes("max_count")) {
            throw new ApiError(429, "OTP request limit exceeded for today");
        }
        throw new ApiError(400, error.message);
    }

    //send otp to user
    const email_content = acc_auth_email_content(generated_otp, requester);
    const email_subject = acc_auth_email_subject()
    
    const send_user_otp = await mailSender(email, email_subject, email_content);
    if(!send_user_otp) throw new ApiError(400, "something went wrong");

    //create otp_reg_token
    otp_token_data.random_id = random_otp_id
    otp_token_data.type ="login";
    otp_token_data.email = email;
    otp_token_data.requester = requester;
    const createOtpToken = await authToken(otp_token_data);
    
    return createOtpToken;
};

const resetPassAuth = async(email, requester)=>{
        //generate otp
        const generated_otp = [...crypto.randomFillSync(new Uint8Array(5))].map(n => n % 10).join('');
    
        //hash the otp
        const hashedOtp = await hashOtp(String(generated_otp));
        
        //save otp and data into db
        const otp_expiry = new Date(Date.now() + 2 * 60 * 1000).toISOString();
        const random_otp_id = crypto.randomBytes(15).toString('base64url').slice(0, 10);
        const hash_id = await hashOtp(random_otp_id);
       
        
        const otp_token_data ={
            otp_expiry,
            random_id:hash_id
        }
    
        try {
            // Step 1: Check existing OTP (if any)
            const existingOtpCheck = await db.query(
                `SELECT 
                token 
                FROM 
                reset_pass_auth 
                WHERE email = $1`,
                [email]
            );
        
            if (existingOtpCheck.rows.length > 0 && existingOtpCheck.rows[0]?.token) {
                const { otp_expiry } = existingOtpCheck.rows[0].token;
                const now = new Date().toISOString();
        
                if (new Date(now) < new Date(otp_expiry)) {
                    throw new ApiError(400, "Previous OTP not yet expired");
                }
            }
        
            // Step 2: Update count only if we're actually sending a new OTP
            await db.query(
                `INSERT INTO auth_request_counts 
                (email, count, created_at)
                 VALUES ($1, 1, now())
                 ON CONFLICT (email) DO UPDATE
                 SET 
                    count = CASE 
                        WHEN auth_request_counts.created_at::date = CURRENT_DATE 
                            THEN auth_request_counts.count + 1 
                        ELSE 1 
                    END,
                    created_at = CASE 
                        WHEN auth_request_counts.created_at::date = CURRENT_DATE 
                            THEN auth_request_counts.created_at 
                        ELSE now() 
                    END`,
                [email]
            );
        
            // Step 3: Upsert OTP (insert or update)
            const upsertOtp = await db.query(
                `INSERT INTO reset_pass_auth 
                (email, otp, requester, token, status)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (email) DO UPDATE
                 SET otp = $2, requester = $3, token = $4, status = $5`,
                [email, hashedOtp, requester, otp_token_data, 'pending']
            );
        
        } catch (error) {
            if (error.message.includes("max_count")) {
                throw new ApiError(429, "OTP request limit exceeded for today");
            }
            throw new ApiError(400, error.message);
        }
    
        //send otp to user
        // const email_content = acc_auth_email_content(generated_otp, requester);
        // const email_subject = acc_auth_email_subject()
        
        // const send_user_otp = await mailSender(email, email_subject, email_content);
        // if(!send_user_otp) throw new ApiError(400, "something went wrong");
    
        //create otp_reg_token
        otp_token_data.random_id = random_otp_id
        otp_token_data.type ="reset-pass";
        otp_token_data.email = email;
        otp_token_data.requester = requester;
        const createOtpToken = await authToken(otp_token_data);
        
        console.log(generated_otp)
        return createOtpToken;
}

const otpManager = async(email, requester, type)=>{
    if(type === "register"){
        const reg_auth_req = await registerAuth(email, requester);
        return reg_auth_req
    };

    if(type === "login"){
        const login_auth_req = await loginAuth(email, requester);
        return login_auth_req
    };

    if(type === "reset-pass"){
        const reset_pass_req = await resetPassAuth(email, requester);
        return reset_pass_req
    }
};

const loginVerify = async(email, otp, random_id, requester)=>{
  
    //get info of user from email
    const email_info = await db.query(
        `SELECT
         id, 
         email,
         otp,
         requester,
         token,
         status
         FROM 
         login_auth
         WHERE email = $1`,[email]
    );
    if(email_info.rowCount === 0) throw new ApiError(400, "something went wrong");
    const status = email_info.rows[0].status;
    if(status === "verified") throw new ApiError(400, "email alreday verified");

    const stored_otp = email_info.rows[0].otp;
    const stored_otp_id = email_info.rows[0].id;
    const stored_requester = email_info.rows[0].requester;
    const stored_random_id =  email_info.rows[0].token.random_id;
    const stored_expiry = email_info.rows[0].otp_expiry;

    //make sure otp is not expired
    if(new Date().toISOString > new Date(stored_expiry)) throw new ApiError(400, "Otp expired");

    //make sure requester type is correct
    if(requester !== stored_requester) throw new ApiError(400, "Unauthorized requester");

    //make random id are same
    const compare_random_id = await bcrypt.compare(String(random_id), stored_random_id);
    if(!compare_random_id) throw new ApiError(400, "Unauthorized access");

    //make sure both otp are same
    const compare_otp = await bcrypt.compare(String(otp), stored_otp);
    if(!compare_otp) throw new ApiError(400, "Wrong otp");

    //generate unique verification id
    const verify_id = crypto.randomBytes(15).toString('base64url').slice(0, 10);
    const hashed_verify_id = await hashOtp(String(verify_id))
    //update the status to verified and store verified_id
    const update_verified = await db.query(
        `UPDATE login_auth 
        SET status = $1, 
        verified_id = $2 
        WHERE id = $3`,['verified', hashed_verify_id, stored_otp_id]
    );

    if(update_verified.rowCount === 0) throw new ApiError(400, "something went wrong");

    const login_token_data ={
        id:stored_otp_id,
        email:email,
        verify_id,
        requester
    }

    //generate login_token 
    const login_token = await authToken(login_token_data);

    return login_token
};

const regVerify = async(email, otp, random_id, requester)=>{
    //get info of user from email
    const email_info = await db.query(
        `SELECT
         id, 
         email,
         otp,
         requester,
         token,
         status
         FROM 
         reg_auth
         WHERE email = $1`,[email]
    );
    if(email_info.rowCount === 0) throw new ApiError(400, "something went wrong");
    const status = email_info.rows[0].status;
    if(status === "verified") throw new ApiError(400, "Email alredy verified")

    const stored_otp = email_info.rows[0].otp;
    const stored_otp_id = email_info.rows[0].id;
    const stored_requester = email_info.rows[0].requester;
    const stored_random_id =  email_info.rows[0].token.random_id;
    const stored_expiry = email_info.rows[0].otp_expiry;

    //make sure otp is not expired
    if(new Date().toISOString > new Date(stored_expiry)) throw new ApiError(400, "Otp expired");

    //make sure requester type is correct
    if(requester !== stored_requester) throw new ApiError(400, "Unauthorized requester");

    //make random id are same
    const compare_random_id = await bcrypt.compare(String(random_id), stored_random_id);
    if(!compare_random_id) throw new ApiError(400, "Unauthorized access");

    //make sure both otp are same
    const compare_otp = await bcrypt.compare(String(otp), stored_otp);
    if(!compare_otp) throw new ApiError(400, "Wrong otp");

    //generate unique verification id
    const verify_id = crypto.randomBytes(15).toString('base64url').slice(0, 10);
    const hashed_verify_id = await hashOtp(String(verify_id))
    //update the status to verified and store verified_id
    const update_verified = await db.query(
        `UPDATE reg_auth 
        SET status = $1, 
        verified_id = $2 
        WHERE id = $3`,['verified', hashed_verify_id, stored_otp_id]
    );

    if(update_verified.rowCount === 0) throw new ApiError(400, "something went wrong");

    const reg_token_data ={
        id:stored_otp_id,
        email:email,
        verify_id,
        requester
    }

    //generate login_token 
    const reg_token = await authToken(reg_token_data);

    return reg_token
};

const resetPassVerify = async(email, otp, random_id, requester)=>{
    //get info of user from email
    const email_info = await db.query(
        `SELECT
         id, 
         email,
         otp,
         requester,
         token,
         status
         FROM 
         reset_pass_auth
         WHERE email = $1`,[email]
    );
    if(email_info.rowCount === 0) throw new ApiError(400, "something went wrong");
    const status = email_info.rows[0].status;
    if(status === "verified") throw new ApiError(400, "Email alredy verified")

    const stored_otp = email_info.rows[0].otp;
    const stored_otp_id = email_info.rows[0].id;
    const stored_requester = email_info.rows[0].requester;
    const stored_random_id =  email_info.rows[0].token.random_id;
    const stored_expiry = email_info.rows[0].otp_expiry;

    //make sure otp is not expired
    if(new Date().toISOString > new Date(stored_expiry)) throw new ApiError(400, "Otp expired");

    //make sure requester type is correct
    if(requester !== stored_requester) throw new ApiError(400, "Unauthorized requester");

    //make random id are same
    const compare_random_id = await bcrypt.compare(String(random_id), stored_random_id);
    if(!compare_random_id) throw new ApiError(400, "Unauthorized access");

    //make sure both otp are same
    const compare_otp = await bcrypt.compare(String(otp), stored_otp);
    if(!compare_otp) throw new ApiError(400, "Wrong otp");

    //generate unique verification id
    const verify_id = crypto.randomBytes(15).toString('base64url').slice(0, 10);
    const hashed_verify_id = await hashOtp(String(verify_id))
    //update the status to verified and store verified_id
    const update_verified = await db.query(
        `UPDATE reset_pass_auth 
        SET status = $1, 
        verified_id = $2 
        WHERE id = $3`,['verified', hashed_verify_id, stored_otp_id]
    );

    if(update_verified.rowCount === 0) throw new ApiError(400, "something went wrong");

    const reset_pass_token_data ={
        id:stored_otp_id,
        email:email,
        verify_id,
        requester
    }

    //generate login_token 
    const reset_pass_token = await authToken(reset_pass_token_data);

    return reset_pass_token
};

const verifyManager = async(type, email, otp, random_id, requester)=>{
    if(type === "register"){
        const reg_auth_req = await regVerify(email, otp, random_id, requester);
        return reg_auth_req
    };

    if(type === "login"){
        const login_auth_req = await loginVerify(email, otp, random_id, requester);
        return login_auth_req
    };

    if(type === "reset-pass"){
        const reset_pass_auth_req = await resetPassVerify(email, otp, random_id, requester);
        return reset_pass_auth_req
    };
};

export {
    otpManager,
    verifyManager,
    registerAuth,
    loginAuth
}
