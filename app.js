require("dotenv").config();

const express = require("express");
const app = express();
app.disable("x-powered-by");
const path = require("path");
const session = require("express-session");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const http = require("http");
const { Server } = require("socket.io");
const rateLimit = require("express-rate-limit");
const axios = require("axios");

const slowDown = require("express-slow-down");





const methodOverride = require("method-override");

app.use(methodOverride("_method"));



// == MODELS ==
const User = require("./models/user");
const Review = require("./models/review");
const Course = require("./models/course");
const Lesson = require("./models/lesson");
const LiveClass = require("./models/liveClass");
const Teacher = require("./models/teacher");

// === UTILS 
const wrapAsync = require("./utils/wrapAsync");
const ExpressError = require("./utils/ExpressError");
const { reviewSchema } = require("./schema");
const { appendFile } = require("fs/promises");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
// === DB CONNECTION
mongoose
  .connect(process.env.MONGO_URL )
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// ==APP CONFIG 
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static(path.join(__dirname, "public")));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

const loginLimiter = slowDown({
  windowMs: 1 * 60 * 1000, // 1 minute
  delayAfter: 3,
  delayMs: (used, req) => {
    const delayAfter = req.slowDown.limit;
    return (used - delayAfter) * 1000; // 1 sec per extra request
  }
});



const validateReview = (req, _res, next) => {
  const { error } = reviewSchema.validate(req.body);
  if (error) {
    throw new ExpressError(
      400,
      error.details.map(e => e.message).join(", ")
    );
  }
  next();
};




//  SESSION 
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      expires: Date.now() + 7 * 24 * 60 * 60 * 1000,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      httpOnly: true
    }
  })
);

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// === ROLE CHECKS 
function isLoggedIn(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/home/login");
  }
  next();
}

function isTeacher(req, res, next) {
  if (!req.session.user || req.session.user.role !== "teacher") {
    return res.status(403).render("error", {
      message: "Access denied"
    });
  }
  next();
}

function isAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).render("error", {
      message: "Access denied"
    });
  }
  next();
}

async function verifyRecaptcha(token) {
  const response = await axios.post(
    "https://www.google.com/recaptcha/api/siteverify",
    null,
    {
      params: {
        secret: process.env.RECAPTCHA_SECRET,
        response: token
      }
    }
  );
  return response.data.success;
}


app.get("/resources", (req, res) => res.render("resources"));
app.get("/contact", (req, res) => res.render("contact"));
app.get("/", (req, res) => res.redirect("/home"));
app.get("/home", (req, res) => res.render("home"));
app.get("/home/aboutus", (req, res) => res.render("aboutus"));


app.get("/home/cookies", (req, res) => res.render("cookies"));
app.get("/home/refund", (req, res) => res.render("refund"));
app.get("/home/privicy", (req, res) => res.render("privicy"));


app.get("/home/course", wrapAsync(async (req, res) => {
  const AllCourses = await Course.find({});
  res.render("course", { AllCourses });
}));

app.get("/notes", (req, res) => res.render("notes"));
app.get("/home/login", (req, res) => res.render("login"));
app.get("/home/signup", (req, res) => res.render("signup"));
app.get("/home/terms", (req, res) => res.render("terms"));



// ratelimiter in login
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 100,
  message: "Too many attempts, try later",
  standardHeaders: true,
  legacyHeaders: false,
});






// REGISTER
app.post(
  "/register",loginLimiter,
  authLimiter,
  wrapAsync(async (req, res) => {

    // 1️⃣ CAPTCHA TOKEN
    const captchaToken = req.body["g-recaptcha-response"];
    if (!captchaToken || !(await verifyRecaptcha(captchaToken))) {
      throw new ExpressError(400, "CAPTCHA verification failed");
    }

    // 2️⃣ Normal register logic
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new ExpressError(409, "User already exists");
    }

    const hash = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      email,
      password: hash
    });

    await user.save();

    // 3️⃣ Session
    req.session.user = {
      _id: user._id,
      username: user.username,
      email: user.email,
      role: user.role
    };

    res.redirect("/home");
  })
);

// ================= GOOGLE AUTH =================

// Start Google Login
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"]
  })
);

// Callback
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/home/login" }),
  (req, res) => {

    // 🔥 Manual session (matches your app logic)
    req.session.user = {
      _id: req.user._id,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role
    };

    res.redirect("/home");
  }
);

// LOGIN
app.post(
  "/login",
  authLimiter,loginLimiter,
  wrapAsync(async (req, res) => {

    
    const captchaToken = req.body["g-recaptcha-response"];
    if (!captchaToken || !(await verifyRecaptcha(captchaToken))) {
      throw new ExpressError(400, "CAPTCHA verification failed");
    }

    
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) throw new ExpressError(401, "User not found");

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      throw new ExpressError(401, "Wrong password");
    }

  
    req.session.user = {
      _id: user._id,
      username: user.username,
      email: user.email,
      role: user.role
    };

    res.redirect("/home");
  })
);


app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/home");
});


// === COURSE VIEW 
app.get("/home/:id", wrapAsync(async (req, res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    return res.status(404).render("error", { message: "Invalid Course URL" });
  }

  const course = await Course.findById(req.params.id).populate({
    path: "reviews",
    populate: { path: "author" }
  });

  if (!course) throw new ExpressError(404, "Course not found");
  res.render("viewcourse", { course });
}));

// === BUY COURSE 
app.post("/courses/:id/buy", wrapAsync(async (req, res) => {
  if (!req.session.user) return res.redirect("/home/login");

  const user = await User.findById(req.session.user._id);
  if (!user.boughtCourses.includes(req.params.id)) {
  user.boughtCourses.push(req.params.id);
}

  await user.save();

  res.redirect("/afterbuy");
}));

app.get("/certificate/:id", wrapAsync(async (req, res) => {
  const { id } = req.params;

  const course = await Course.findById(id)
    .populate("CourseOwnerName"); // 🔥 REQUIRED

  if (!course) throw new ExpressError(404, "Course not found");

  res.render("certificate", { course });
}));


// == INSIDE COURSE 
app.get("/insidecourse/:id", wrapAsync(async (req, res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    return res.status(404).render("error", { message: "Invalid Course URL" });
  }

  if (!req.session.user) return res.redirect("/home/login");

  const course = await Course.findById(req.params.id);
  if (!course) throw new ExpressError(404, "Course not found");

  const lessons = await Lesson.find({ course: course._id }).sort({ order: 1 });

  res.render("insidecourse", { course, lessons });
}));


// = REVIEWS 
app.post(
  "/courses/:id/reviews",
  validateReview,
  wrapAsync(async (req, res) => {
    if (!req.session.user) return res.redirect("/home/login");

    const course = await Course.findById(req.params.id);
    const user = await User.findById(req.session.user._id);

    const review = new Review(req.body.review);
    review.author = user._id;

    course.reviews.push(review);
    await review.save();
    await course.save();

    res.redirect(`/home/${course._id}`);
  })
);


// ================= LIVE CLASS ==========
app.post("/course/:id/start-live", wrapAsync(async (req, res) => {
  if (!req.session.user) return res.redirect("/home/login");

  const roomId = "live-" + Date.now();

  const liveClass = new LiveClass({
    course: req.params.id,
    teacher: req.session.user._id,
    roomId,
    isLive: true,
    startedAt: new Date()
  });

  await liveClass.save();
  res.redirect(`/course/${req.params.id}/live`);
}));

app.get("/course/:id/live", wrapAsync(async (req, res) => {
  const course = await Course.findById(req.params.id);
  if (!course) throw new ExpressError(404, "Course not found");

  const liveClass = await LiveClass.findOne({
    course: course._id,
    isLive: true
  });

  if (!liveClass) return res.send("Live class not started yet");
  res.render("liveClass", { course, liveClass });
}));
// / ================= BECOME TEACHER =================
app.get("/become-teacher", isLoggedIn, (req, res) => {
  res.render("teacher/becomeTeacher");
});

app.post("/become-teacher", isLoggedIn, async (req, res) => {
  const { bio, expertise, experience } = req.body;

  const teacher = new Teacher({
    user: req.session.user._id,
    bio,
    expertise: expertise.split(","),
    experience
  });

  await teacher.save();
  res.send("Teacher request sent. Wait for admin approval.");
});

// ================= ADMIN =================
app.get("/admin/dashboard", isAdmin, (req, res) => {
  res.render("admin/dashboard");
});
app.get("/admin/teachers", isAdmin, async (req, res) => {
  const teachers = await Teacher.find({ approved: false })
    .populate("user");

  res.render("admin/teacherRequests", { teachers });
});

app.get("/admin/users", isAdmin, async (req, res) => {
  const users = await User.find({});
  res.render("admin/users", { users });
});

app.get("/admin/courses", isAdmin, async (req, res) => {
  const courses = await Course.find({}).populate("teacher");
  res.render("admin/courses", { courses });
});

app.post("/admin/teacher/approve/:id", isAdmin, async (req, res) => {
  const teacher = await Teacher.findById(req.params.id);
  teacher.approved = true;
  await teacher.save();

  await User.findByIdAndUpdate(teacher.user, { role: "teacher" });
  res.redirect("/admin/teachers");
});
app.post("/admin/course/delete/:id", isAdmin, async (req, res) => {
  await Course.findByIdAndDelete(req.params.id);

  // optional: delete lessons also
  await Lesson.deleteMany({ course: req.params.id });

  res.redirect("/admin/dashboard");
});



// ================= TEACHER =================
app.get("/teacher/dashboard", isTeacher, async (req, res) => {
  const teacher = await Teacher.findOne({ user: req.session.user._id }).populate("user");
  const courses = await Course.find({ teacher: teacher._id });
  res.render("teacher/dashboard", { teacher, courses });
});

app.get("/teacher/course/new", isTeacher, (req, res) => {
  res.render("teacher/newCourse");
});

app.post("/teacher/course/new", isTeacher, async (req, res) => {
  const teacher = await Teacher.findOne({ user: req.session.user._id });

  const course = new Course({
    title: req.body.title,
    description: req.body.description,
    price: req.body.price,
    thumbnail: req.body.thumbnail,
    teacher: teacher._id
  });

  await course.save();
  res.redirect("/teacher/dashboard");
});

app.get("/teacher/course/:id/lesson/new", isTeacher, async (req, res) => {
  const course = await Course.findById(req.params.id);
  res.render("teacher/newLesson", { course });
});

app.post("/teacher/course/:id/lesson/new", isTeacher, async (req, res) => {
  const { title, videoUrl } = req.body;

  const lessonCount = await Lesson.countDocuments({
    course: req.params.id
  });

  const lesson = new Lesson({
    title,
    videoUrl,
    order: lessonCount + 1,
    course: req.params.id
  });

  await lesson.save();
  res.redirect("/teacher/dashboard");
});



// ================= STUDENT =================
app.get("/afterbuy", async (req, res) => {
  if (!req.session.user) return res.redirect("/home/login");

  const user = await User.findById(req.session.user._id).populate("boughtCourses");
  const liveClasses = await LiveClass.find({ isLive: true });

  res.render("afterBuy", { user, liveClasses });
});


// ================= ERRORS =================

// 404 – Not Found
app.use((req, res) => {
  res.status(404).render("error", {
    message: "Page Not Found"
  });
});

// Global Error Handler (NO stack traces exposed)
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;

  // Log full error only on server
  console.error(err);

  // Send safe message to user
  res.status(statusCode).render("error", {
    message:"Something went wrong. Please try again later."
  });
});

// ================= SOCKET =================
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // change to your domain in production
    methods: ["GET", "POST"]
  },
  pingTimeout: 20000,
  pingInterval: 25000
});

// ================= SOCKET SECURITY LAYERS =================

// 1️⃣ AUTH CHECK (VERY IMPORTANT)
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;

  if (!token) {
    console.log("❌ Socket rejected: No token");
    return next(new Error("Unauthorized"));
  }

  // OPTIONAL: verify JWT / Clerk token here
  // For now, token presence check is enough
  next();
});

// 2️⃣ CONNECTION LIMIT (ANTI-FLOOD)
const MAX_CONNECTIONS = 100;

io.on("connection", (socket) => {

  if (io.engine.clientsCount > MAX_CONNECTIONS) {
    console.log("❌ Too many socket connections");
    socket.disconnect(true);
    return;
  }

  console.log("✅ User connected:", socket.id);

  // 3️⃣ RATE-LIMIT EVENTS (ANTI-SPAM)
  let eventCount = 0;
  const EVENT_LIMIT = 20;

  const rateLimit = () => {
    eventCount++;
    if (eventCount > EVENT_LIMIT) {
      console.log("❌ Socket spam detected:", socket.id);
      socket.disconnect(true);
    }
  };

  // Reset counter every 10 seconds
  const resetInterval = setInterval(() => {
    eventCount = 0;
  }, 10000);

  // ================= SOCKET EVENTS =================

  socket.on("join-room", (roomId) => {
    rateLimit();

    if (!roomId || typeof roomId !== "string") return;

    socket.join(roomId);

    socket.to(roomId).emit("user-joined", socket.id);

    const count = io.sockets.adapter.rooms.get(roomId)?.size || 0;
    io.to(roomId).emit("user-count", count);
  });

  socket.on("offer", ({ to, offer }) => {
    rateLimit();
    if (!to || !offer) return;

    io.to(to).emit("offer", { from: socket.id, offer });
  });

  socket.on("answer", ({ to, answer }) => {
    rateLimit();
    if (!to || !answer) return;

    io.to(to).emit("answer", { from: socket.id, answer });
  });

  socket.on("ice-candidate", ({ to, candidate }) => {
    rateLimit();
    if (!to || !candidate) return;

    io.to(to).emit("ice-candidate", { from: socket.id, candidate });
  });

  socket.on("disconnect", () => {
    clearInterval(resetInterval);
    console.log("🔌 User disconnected:", socket.id);
  });
});

port = process.env.PORT;
// ================= SERVER =================
async function startServer() {
  try {
    app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  }); 
  } catch (error) {
    console.error("Failed to start server:", error);
    
  }  

} 
startServer();