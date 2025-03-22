export const access_options = {
    httpOnly: true,
    secure: false,
    maxAge: 1 * 24 * 60 * 60 * 1000 // 10 days
  };

  export const refres_options = {
    httpOnly: true,
    secure: false,
    maxAge: 10 * 24 * 60 * 60 * 1000 // 10 days
  };

export const session_options = {
  httpOnly:true,
  secure:false
}

export const acc_auth_email_subject = ()=>{
  const header = `Your Otp from open-bike-se`
  return header
}
export const acc_auth_email_content= (otp, requester)=>{
    const emailText = `Dear ${requester},
Your one-time password (OTP) for verification is: ${otp}
Please do not share this code with anyone. It is valid for 2 minutes.
If you did not request this code, please ignore this message.
Thank you for choosing Open-bike-se.
Best regards,  
Team open-bike-se`

    return emailText
}


