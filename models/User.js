import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String, // only for email/password users
  image: String,    // profile pic for Google users
});

export default mongoose.models.User || mongoose.model("User", UserSchema);
