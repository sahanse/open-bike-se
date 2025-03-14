const authEmailContent=(otp)=>{
    const emailText = `Dear User,
    Your one-time password (OTP) for verification is: ${otp}
    Please do not share this code with anyone. It is valid for 3 minutes.
    If you did not request this code, please ignore this message.
    Thank you for choosing Open-bike-se.
    Best regards,  
    Team open-bike-se`

    return emailText
}

export {authEmailContent}
