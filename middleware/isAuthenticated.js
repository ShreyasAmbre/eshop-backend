import { User } from "../models/userModels.js";
import jwt from 'jsonwebtoken';

export const isAuthenticated = async(req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer")) {
      res.status(400).json({
        status: false,
        message: "Authorization token is missing or invalid",
      });
    }

    const token = authHeader.split(" ")[1];
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.SECRET_KEY);
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        res.status(400).json({
          status: false,
          message: "The registration token has expired",
        });
      }
      return res.status(400).json({
        status: false,
        message: "Access token is missing or invalid",
      });
    }

    const user = await User.findById(decoded.id);
    if(!user){
      return res.status(400).json({
        success: false,
        message: "User not found"
      })
    }

    req.id = user.id;
    req.user = user;
    next();
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    })
  }
}

export const isAdmin = async(req, res, next) => {
  try {
    if(req.user && req.user.role === 'admin'){
      next();
    }else {
      res.status(400).json({
        success: false,
        message: "Access denied: Admin Only"
      })
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    })
  }
}
