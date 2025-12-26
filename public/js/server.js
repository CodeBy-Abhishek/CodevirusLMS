const express = require("express");
const path = require("path");
const app = express();

// PUBLIC STATIC FILES
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MAIN PAGE
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// ADMIN PAGE
app.get("/admin", (req, res) => {
    res.sendFile(path.join(__dirname, "AdminPanel.html"));
});

// STUDENT RECORD PAGE
app.get("/student-record", (req, res) => {
    res.sendFile(path.join(__dirname, "StudentRecord.html"));
});

// PAYMENT PAGE
app.get("/payment", (req, res) => {
    res.sendFile(path.join(__dirname, "Payment.html"));
});

// RUN SERVER
app.listen(3000, () => {
    console.log("Server running at http://localhost:3000");
});
