
const mongoose = require("mongoose");

const teacherSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },

  bio: String,
  expertise: [String],
  experience: Number,

  approved: {
    type: Boolean,
    default: false
  }
});

module.exports = mongoose.model("Teacher", teacherSchema);
