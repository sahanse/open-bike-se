import {Router} from "express"
import {generateOtp, verifyOtp} from "../controllers/Acc_auth.controller.js"
import {verifyAccAuth} from "../middlewares/Auth.middleware.js"

const router = Router();

router.route("/getOtp").get(verifyAccAuth, generateOtp)
router.route("/verifyOtp").post(verifyAccAuth, verifyOtp);

export default router;


