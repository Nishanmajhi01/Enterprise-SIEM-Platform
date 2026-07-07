const express=require("express");

const router=express.Router();


const {
analyseThreat
}=require("../controllers/threatController");



router.post(
"/analyse",
analyseThreat
);



module.exports=router;