import db from "../db/index.js"
import {mailSender} from "../utils/MailManager.js"
import crypto from "crypto"
import {hashOtp, compareOtp} from "../utils/Bcrypt.js"

import {ApiError} from "../utils/ApiError.js"

const resePassFunc = async(user_id, email, expiry)=>{
        const user_email = email;
        const existing_otp_expiry = expiry;

        if(existing_otp_expiry){
            const curr_date = new Date().toISOString();
            if(new Date(curr_date) < new Date(existing_otp_expiry)){
                throw new ApiError(400, "previous otp not yet expired")
            }else{
                const deletePreviousOtp = await db.query(
                    `DELETE FROM 
                    reset_pass_otp
                    WHERE user_id = $1`,[user_id]
                )
                if(deletePreviousOtp.rowCount === 0) throw new ApiError(400, "something went wrong")
            }
        }
        
        //generate otp 
        const otp = crypto.randomInt(10000, 100000);
        const unique_id = crypto.randomInt(10000, 100000);
        const hashed_otp = await hashOtp(String(otp));
        const curr_date = new Date().toISOString();
        const expiry_date = new Date(Date.now() + 3 * 60000).toISOString();

        //save the hashed otp in otp table
        const saveOtp = await db.query(
            `INSERT INTO reset_pass_otp 
            (user_id, 
            otp, 
            unique_id, 
            created_at, 
            expiry_at)
            VALUES ($1, $2, $3, $4, $5) RETURNING user_id, unique_id`,
            [user_id, hashed_otp, unique_id, curr_date, expiry_date]
        );

        if(saveOtp.rowCount === 0) throw new ApiError(400, 'something went wrong');

        const stored_user_id = saveOtp.rows[0].user_id;
        const stored_unique_id = saveOtp.rows[0].unique_id;

         //send otp to user email
         let emailSubject = 'Your Otp from open-bike-se'
         
         const emailText = authEmailContent(otp)

        // //send otp to user
        // const sendOtp = await mailSender(user_email, emailSubject, emailText);
        // if(!sendOtp) throw new ApiError(400, "something went wrong");

        //generate otpToken
        const otpToken = await createOtpToken({user_id:stored_user_id, unique_id:stored_unique_id});
        if(!otpToken) throw new ApiError(400, 'something went wrong');

        console.log(otp)
        return otpToken
}

export default resePassFunc
