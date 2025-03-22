import {Router} from "express"
import { upload } from "../middlewares/multer.middleware.js";
import {verifyRider} from "../middlewares/Auth.middleware.js"
import {
    riderRegister,
    riderLogin,
    riderLogout,
    refreshAccessToken,
    riderAccDelete,
    updateInfo,
    updateCreticalInfo,
    updateImage,
    resetPass
} from "../controllers/rider.controllers.js"

const router = Router();

router.route("/register").post(upload.single("rider_image"),riderRegister)
router.route("/login").post(riderLogin);
router.route("/refreshAccessToken").put(refreshAccessToken)

//secured routes
router.route("/logout").post(verifyRider, riderLogout)
router.route("/deleteAcc").delete(verifyRider,riderAccDelete)
router.route("/updateInfo").patch(verifyRider,updateInfo)
router.route("/updateCredential").patch(verifyRider,updateCreticalInfo)
router.route("/updateImage").patch(verifyRider, upload.single("rider_image"), updateImage)
router.route("/resetPass").patch(resetPass)

export default router;