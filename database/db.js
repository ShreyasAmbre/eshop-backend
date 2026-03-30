import mongoose, { Mongoose } from "mongoose";
import 'dotenv/config';

const connectDB = async() => {
    try {
        await mongoose.connect(`${process.env.MONGO_URI}/eshop-yt`);
        console.log("MongoDB Conencted Successfully");    
    } catch (error) {
        console.log("MongoDB Connection Failed: ", error)
    }
}

export default connectDB;