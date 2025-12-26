
const mongoose = require("mongoose");
const Course = require("../models/course");
const data = require("./data");

async function main() {
  await mongoose.connect("mongodb://127.0.0.1:27017/LMSproject");
  console.log("Connected to MongoDB");
}

async function initDB() {
  await main();

  await Course.deleteMany({});
  console.log("Old courses removed.");

  await Course.insertMany(data);
  console.log("New courses added.");

  mongoose.connection.close();
}

initDB();
