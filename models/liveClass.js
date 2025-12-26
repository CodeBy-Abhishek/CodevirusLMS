const mongoose = require("mongoose");

const liveClassSchema = new mongoose.Schema({
  course: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Course",
    required: true
  },
  teacher: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  roomId: {
    type: String,
    required: true
  },
  isLive: {
    type: Boolean,
    default: false
  },
  startedAt: Date
});

module.exports = mongoose.model("LiveClass", liveClassSchema);
