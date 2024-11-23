require("dotenv").config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require("cors");



const app = express();

const User = [{username:"user1",hashedPassword:"$2b$12$Nduf7vgc3VfNSCyEiPvFJ.BocE9QU3u9KYMGrn6cKMTlOSfegtCBO"}]
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(cors());
const authenticateJWT = (req,res,next)=>{
    const {authorization: token} = req.headers;
    jwt.verify(token,process.env.SECRET,(err,user)=>{
        if(err) return res.status("403").json({"message":"Auth Token Expired"});
        next();
    })
}

const PORT = 4500;


app.post('/user/generate',async(req,res)=>{
    const {password}=req.body;
    console.log("Hit    ",password)
    const hashedPassword = await bcrypt.hash(password,12);
    console.log(hashedPassword)
    res.status(200).json({hashedPassword});
})

app.post("/user/login",async (req,res)=>{
    const {username,password}=req.body;
    if(username==undefined || password==undefined) return res.status(400).json({message:"Bad Request, Empty Fields"});
    const currentUser = User.find((user)=> user.username===username )
    if(currentUser==undefined) return res.status(403).json({"message":"User Does not exist"});
    if(await bcrypt.compare(password,currentUser.hashedPassword)) 
    {
        const token = jwt.sign({username,password},process.env.SECRET,{expiresIn:"1h"});
        return res.status(200).json({message:" Password matched, Successfully Logged in",token});
    }
    else return res.status(403).json({message:"Invalid Credentials "});
})

app.post("/user/check",authenticateJWT,async(req,res)=>{
    return res.status(200).json({message:"Valid Token"});
})

app.listen(PORT,(()=>{
    console.log("Server started on PORT ",PORT);
}))
