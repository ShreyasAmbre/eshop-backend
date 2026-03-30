import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    profilePic: { type: String, default: "" }, // Clouduinary image url
    profilePicPublicId: { type: String, default: "" }, // Clouduinary public id for delete, update and add actions
    email: { type: String, required: true, uniques: true },
    password: { type: String, required: true },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    token: { type: String, default: null },
    isVerified: { type: Boolean, default: false },
    isLoggedIn: { type: Boolean, default: false },
    otp: { type: String, default: null },
    otpExpiry: { type: Date, default: null },
    address: { type: String },
    city: { type: String },
    zipcode: { type: String },
    phoneNo: { type: String },
  },
  { timestamps: true },
);

export const User = mongoose.model("User", userSchema)
