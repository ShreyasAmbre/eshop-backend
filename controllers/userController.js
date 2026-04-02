import { User } from "../models/userModels.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { verifyEmail } from "../emailVerify/verifyEmail.js";
import "dotenv/config";
import { Session } from "../models/sessionModels.js";
import { sendOtpEmail } from "../emailVerify/sendOtpMail.js";

export const register = async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    const user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({
        success: false,
        message: "User already present",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
    });

    const token = jwt.sign({ id: newUser._id }, process.env.SECRET_KEY, {
      expiresIn: "10m",
    });
    verifyEmail(token, newUser.email); // send email verify here
    newUser.token = token;

    await newUser.save();
    return res.status(201).json({
      success: true,
      message: "User created successfully",
      user: newUser,
    });

  } catch (error) {
    console.log("Register User Failed", error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

export const verify = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer")) {
      return res.status(400).json({
        status: false,
        message: "Authorization token Invalid",
      });
    }

    const token = authHeader.split(" ")[1];
    let decode;
    try {
      decode = jwt.verify(token, process.env.SECRET_KEY);
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        return res.status(400).json({
          status: false,
          message: "The registration token has expired",
        });
      }
      return res.status(400).json({
        status: false,
        message: "Token verification failed",
      });
    }
    const user = await User.findById(decode.id);
    if (!user) {
      return res.status(400).json({
        status: false,
        message: "User not found",
      });
    }

    user.token = null;
    user.isVerified = true;

    await user.save();
    return res.status(200).json({
      status: true,
      message: "User email verified successfully",
    });
  } catch (error) {
    return res.status(500).json({
      status: false,
      message: error.message,
    });
  }
};

export const reVerify = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        status: false,
        message: "User not found",
      });
    }

    const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, {
      expiresIn: "10m",
    });
    verifyEmail(token, user.email); // send email verify here
    user.token = token;
    await user.save();
    return res.status(200).json({
      status: true,
      message: "Verification email sent again successfully",
      token: user.token,
    });
  } catch (error) {
    return res.status(500).json({
      status: false,
      message: error.message,
    });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    const existingUser = await User.findOne({ email });
    if (!existingUser) {
      return res.status(400).json({
        success: false,
        message: "User not found",
      });
    }
    console.log("REQ =>", req.body, existingUser.password);

    const isPasswordValid = await bcrypt.compare(
      password,
      existingUser.password,
    );

    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    if (!existingUser.isVerified) {
      return res.status(400).json({
        success: false,
        message: "Verify your account then try to login",
      });
    }

    // Generate token
    const accessToken = jwt.sign(
      { id: existingUser.id },
      process.env.SECRET_KEY,
      { expiresIn: "10d" },
    );
    const refreshToken = jwt.sign(
      { id: existingUser.id },
      process.env.SECRET_KEY,
      { expiresIn: "30d" },
    );

    existingUser.isLoggedIn = true;
    await existingUser.save();

    // Delete session if present and then create new session after login success
    const existingSession = await Session.findOne({ userId: existingUser.id });
    if (existingSession) {
      await Session.deleteOne({ userId: existingUser.id });
    }

    await Session.create({ userId: existingUser.id });
    return res.status(200).json({
      success: true,
      message: `Welcome Back ${existingUser.firstName}`,
      user: existingUser,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

export const logout = async (req, res) => {
  try {
    // this req.id is coming from isAuthenticated middleware
    const userId = req.id;

    await Session.deleteMany({ userId: userId });
    await User.findByIdAndUpdate(userId, { isLoggedIn: false });
    return res.status(200).json({
      success: true,
      message: "User logout successfully",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email })
    if(!user){
      return res.status(400).json({
        success: false,
        message: "User with this email not found",
      });
    }

    const otp = Math.floor(100000 + Math.random()*900000).toString();
    const otpExpiry = new Date(Date.now()+10+60*1000);
    user.otp = otp;
    user.otpExpiry = otpExpiry;

    await user.save();
    await sendOtpEmail(otp, email);

    return res.status(200).json({
      success: true,
      message: "OTP send to email successfully",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};


export const verifyOtp = async(req, res) => {
  try {
    const { otp } = req.body;
    const email = req.params.email;
    if(!otp){
      return res.status(400).json({
        success: false,
        message: "OTP is required",
      });
    }

    const user = await User.findOne({ email });
    if(!user){
      return res.status(400).json({
        success: false,
        message: "User email not found",
      });
    }


    if(!user.otp || !user.otpExpiry){
      return res.status(400).json({
        success: false,
        message: "OTP is not generated or already verified",
      });
    }

    if(user.otpExpiry < new Date()){
      return res.status(400).json({
        success: false,
        message: "OTP expired, please request for new OTP",
      });
    }

    if(otp !== user.otp){
      return res.status(400).json({
        success: false,
        message: "OTP is invalid",
      });
    }

    user.otp = null;
    user.otpExpiry = null;
    await user.save();
    return res.status(200).json({
      success: true,
      message: "OTP verified successfully",
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
}

export const changePassword = async(req, res) => {
  try {
    const { newPassword, confirmPassword } = req.body;
    const email = req.params.email;

    const user = await User.findOne({ email });
    if(!user){
      return res.status(400).json({
        success: false,
        message: "User email not found",
      });
    }

    if(!newPassword || !confirmPassword){
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

     if(newPassword !== confirmPassword){
      return res.status(400).json({
        success: false,
        message: "Password does not match",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    return res.status(200).json({
      success: false,
      message: "Password changed successfully",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
}

export const allUsers = async(req, res) => {
  try {
    const users = await User.find();
    return res.status(200).json({
      success: true,
      users,
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
}

export const getUserById = async(req, res) => {
  try {
    const { userId } = req.params;
    // select is used when some field we don't want to send in response
    const user = await User.findById(userId).select("-password -otp -otpExpiry -token");

    if(!user){
      return res.status(400).json({
        success: false,
        message: "User not found",
      });
    }

    return res.status(200).json({
      status: true,
      message: "",
      user,
    })

  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
}
