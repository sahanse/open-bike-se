import jwt from "jsonwebtoken"

const createAccessToken = (access_data)=>{
    return jwt.sign(access_data, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn:process.env.ACCESS_TOKEN_EXPIRY
    })
}

const createRefreshToken = (refresh_data)=>{
    return jwt.sign(refresh_data, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn:process.env.REFRESH_TOKEN_EXPIRY
    })
}

const createToken = async(access_data, refres_data)=>{

    const accessToken = createAccessToken(access_data);
    const refreshToken = createRefreshToken(refres_data);
    return {
        accessToken,
        refreshToken
    }
};

const createOtpToken = async(otpData)=>{
    return jwt.sign(otpData, process.env.OTP_TOKEN_SECRET, {
        expiresIn:process.env.OTP_TOKEN_EXPIRY
    })
}

const resetPass_accesToken = async(tokenData)=>{
    return jwt.sign(tokenData, process.env.RESET_PASS_TOKEN_SECRET, {
        expiresIn:process.env.RESET_PASS_TOKEN_EXPIRY
    })
}

export {
    createAccessToken, 
    createRefreshToken, 
    createToken, 
    createOtpToken,
    resetPass_accesToken
}
