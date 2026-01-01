const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const userSchema = new Schema({
  username: {
    type: String,
    required: true
  },

  email: {
    type: String,
    required: true,
    unique: true
  },

  password: {
    type: String,
    required: true
  },

  boughtCourses: [
    {
      type: Schema.Types.ObjectId,
      ref: "Course"
    }
  ],

  role: {
    type: String,
    enum: ["student", "teacher", "admin"],
    default: "student"
  },

  // 🔐 EMAIL VERIFICATION FIELDS
  isVerified: {
    type: Boolean,
    default: false
  },

  emailToken: {
    type: String
  },

  emailTokenExpiry: {
    type: Date
  }
});

module.exports = mongoose.model("User", userSchema);
