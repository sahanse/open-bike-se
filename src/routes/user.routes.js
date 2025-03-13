import {Router} from "express"
import { upload } from "../middlewares/multer.middleware.js";
import {verifyUser} from "../middlewares/Auth.middleware.js"
import {
    user_login, 
    userLocalRegister,
    userOtpAuth,
    googleRegister,
    update_info,
    update_credential,
    update_user_image,
    reset_pass,
    resetPassAuth,
    user_logout,
    delete_account,
    refreshAccessToken
} from "../controllers/user.controller.js"

const router = Router();

router.route("/register/local").post(upload.single("user_image"),userLocalRegister);
router.route("/userOtpAuth").post(userOtpAuth)
router.route("/register/google").post(googleRegister);
router.route("/login").post(user_login);
router.route("/refreshAccessToken").post(refreshAccessToken)

//secured routes
router.route("/logout").post(verifyUser, user_logout)
router.route("/delete-account").delete(verifyUser, delete_account)
router.route("/update-info").patch(verifyUser, update_info)
router.route("/update_credential").patch(verifyUser, update_credential)
router.route("/update_user_image").patch(verifyUser, upload.single("user_image"), update_user_image)
router.route("/resetPassAuth").post(verifyUser, resetPassAuth)
router.route("/reset-pass").patch(verifyUser, reset_pass)

export default router;

