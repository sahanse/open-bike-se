import fs from "fs"
import {ApiError} from "../utils/ApiError.js"

const StrictBodyVerify = async(body, requiredFields, reqFile)=>{
    const bodyKeys = Object.keys(body);
    
    //make sure all required fields are available
    for(let val of requiredFields){
        if(bodyKeys.includes(val) === false){
            if(reqFile){
                fs.unlinkSync(reqFile.path)
            }
            throw new ApiError(400, `field ${val} is required`)
        }
    }

    //make sure all required fields are not null
    for(let val in body){
        if(String(body[val]).trim()===""){
            if(reqFile){
                fs.unlinkSync(reqFile.path)
            }
            throw new ApiError(400, `received null at field ${val}`)
        }
    }

}

export {StrictBodyVerify}
