const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const attendanceSchema = new Schema({
  course: {
    type: Schema.Types.ObjectId,
    ref: "Course",
    required: true
  },
  lesson: {
    type: Schema.Types.ObjectId,
    ref: "Lesson"
  },
  student: {
    type: Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  date: {
    type: Date,
    default: Date.now
  },
  status: {
    
    type: String,
    enum: ["present", "absent"],
    default: "present"
  }
});

module.exports = mongoose.model("Attendance", attendanceSchema);
