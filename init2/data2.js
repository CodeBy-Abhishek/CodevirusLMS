const mongoose = require("mongoose");

module.exports = [

  // ================= CYBERSECURITY FUNDAMENTALS =================
  {
    title: "Introduction to Cybersecurity",
    videoUrl: "/vidio/html.mp4",
    course: new mongoose.Types.ObjectId("6940438387314c1dd64faa18"),
    order: 1
  },
  {
    title: "Cyber Threats & Attacks",
    videoUrl: "/vidio/html.mp4",
    course: new mongoose.Types.ObjectId("6940438387314c1dd64faa18"),
    order: 2
  },
  {
    title: "Security Principles",
    videoUrl:  "/vidio/html.mp4",
    course: new mongoose.Types.ObjectId("6940438387314c1dd64faa18"),
    order: 3
  },

  // ================= NETWORKING & LINUX BASICS =================
  {
    title: "Networking Introduction",
    videoUrl: "/vidio/data.mp4",
    course: new mongoose.Types.ObjectId("6940438387314c1dd64faa19"),
    order: 1
  },
  {
    title: "TCP/IP & Ports",
    videoUrl: "/vidio/data.mp4",
    course: new mongoose.Types.ObjectId("6940438387314c1dd64faa19"),
    order: 2
  },
  {
    title: "Linux Command Line",
    videoUrl: "/vidio/data.mp4",
    course: new mongoose.Types.ObjectId("6940438387314c1dd64faa19"),
    order: 3
  },

  // ================= ETHICAL HACKING BASICS =================
  {
    title: "Introduction to Ethical Hacking",
    videoUrl: "/vidio/ai.mp4",
    course: new mongoose.Types.ObjectId("6940438387314c1dd64faa1a"),
    order: 1
  },
  {
    title: "Reconnaissance Techniques",
    videoUrl: "/vidio/ai.mp4",
    course: new mongoose.Types.ObjectId("6940438387314c1dd64faa1a"),
    order: 2
  },
  {
    title: "Exploitation Basics",
    videoUrl: "/vidio/ai.mp4",
    course: new mongoose.Types.ObjectId("6940438387314c1dd64faa1a"),
    order: 3
  },

  // ================= BLUE TEAM & SOC ANALYST =================
  {
    title: "SOC Overview",
    videoUrl: "/vidio/vid.mp4",
    course: new mongoose.Types.ObjectId("6940438387314c1dd64faa1b"),
    order: 1
  },
  {
    title: "Log Monitoring",
    videoUrl:"/vidio/vid.mp4",
    course: new mongoose.Types.ObjectId("6940438387314c1dd64faa1b"),
    order: 2
  },
  

];
