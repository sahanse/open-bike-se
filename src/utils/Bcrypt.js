import bcrypt from "bcrypt"

const hashPass = async(password)=>{
    return bcrypt.hash(password, 10)
}

const comparePass = async(user_password, hashed_password)=>{
    return bcrypt.compare(user_password, hashed_password)
}

const hashOtp = async(otp)=>{
    return bcrypt.hash(otp, 10)
}

const compareOtp = async(user_otp, hashed_otp)=>{
    return bcrypt.compare(user_otp, hashed_otp)
}

export {hashPass, comparePass, hashOtp, compareOtp};


