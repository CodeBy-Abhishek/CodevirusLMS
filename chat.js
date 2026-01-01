// const express = require("express");
// const router = express.Router();
// const SYSTEM_PROMPT = require("../systemprompt");

// router.post("/chat", async (req, res) => {
//   const userMessage = req.body.message.toLowerCase();

//   let reply = "";

//   //  STRICT ROLE-BASED RESPONSES
//   if (userMessage.includes("services")) {
//     reply =
//       "CODE VIRUS SECURITY (CYBX) provides cybersecurity consulting, threat detection, incident response, and security awareness services to help organizations stay protected. We’re here to support your security needs.";
//   }

//   else if (userMessage.includes("cyber attack")) {
//     reply =
//       "If you suspect a cyberattack, it’s important to act quickly. CYBX can assist with incident response, threat containment, and recovery to minimize impact. You’re taking the right step by reaching out.";
//   }

//   else if (userMessage.includes("training") || userMessage.includes("how are you trained")) {
//     //  constraint enforcement
//     reply =
//       "I’m here to assist with cybersecurity-related questions and services offered by CODE VIRUS SECURITY. Please let me know how I can help you stay secure.";
//   }

//   else {
//     //  fallback
//     reply =
//       "I'm here to help with cybersecurity-related questions and services offered by CODE VIRUS SECURITY. Please let me know how I can assist you in staying secure.";
//   }

//   res.json({ reply });r
// });

// module.exports = router;
