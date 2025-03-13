import jwt from "jsonwebtoken"

const createAccessToken = (access_data)=>{
    return jwt.sign(access_data, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn:process.env.ACCESS_TOKEN_EXPIRY
    })
}

const createRefreshToken = (refres_data)=>{
    return jwt.sign(refres_data, process.env.REFRESH_TOKEN_SECRET, {
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

export {createAccessToken, createRefreshToken, createToken}
