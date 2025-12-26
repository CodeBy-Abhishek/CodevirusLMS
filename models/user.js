const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const userSchema = new Schema({
  username: String,
  email: String,
  password: String,

  boughtCourses: [
    {
      type: Schema.Types.ObjectId,
      ref: "Course"
    }
  ],

  // ✅ NEW (Teacher / Admin support)
  role: {
    type: String,
    enum: ["student", "teacher", "admin"],
    default: "student"
  }
});

module.exports = mongoose.model("User", userSchema);
