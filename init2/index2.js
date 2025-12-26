const mongoose = require("mongoose");
const Lesson = require("../models/lesson");
const Course = require("../models/course");
const data = require("./data2");

mongoose.connect("mongodb://127.0.0.1:27017/LMSproject")
  .then(async () => {
    await Lesson.deleteMany({});   
    await Lesson.insertMany(data); 
    console.log("✅ Lessons inserted successfully");
    mongoose.connection.close();
  })
  .catch(err => console.log(err));
