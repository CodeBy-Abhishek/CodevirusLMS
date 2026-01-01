const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const courseSchema = new Schema(
  {
    title: {
      type: String,
      required: true
    },
    description: {
      type: String,
      required: true
    },
    price: {
      type: Number,
      required: true
    },
    thumbnail: {
      type: String,
      required: true
    },

    category: {
      type: String,
      default: "Cyber Security"
    },

    lessonsCount: {
      type: Number,
      default: 0
    },

  
    teacher: {
      type: Schema.Types.ObjectId,
      ref: "Teacher"
    },
    CourseOwnerName: {
      type: Schema.Types.ObjectId,
      ref: "User"
    },

    reviews: [
      {
        type: Schema.Types.ObjectId,
        ref: "Review"
      }
    ]
  },
  { timestamps: true }
);

module.exports = mongoose.model("Course", courseSchema);
