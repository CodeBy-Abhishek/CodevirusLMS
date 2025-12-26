
const express = require("express");
const app = express();
const path = require("path");
const session = require("express-session");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const http = require("http");
const { Server } = require("socket.io");

// == MODELS ==
const User = require("./models/user");
const Review = require("./models/review");
const Course = require("./models/course");
const Lesson = require("./models/lesson");
const LiveClass = require("./models/liveClass");
const Teacher = require("./models/Teacher");

// === UTILS 
const wrapAsync = require("./utils/wrapAsync");
const ExpressError = require("./utils/ExpressError");
const { reviewSchema } = require("./schema");

// === DB CONNECTION
mongoose
  .connect("mongodb://127.0.0.1:27017/LMSproject")
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// ==APP CONFIG 
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // ✅ FIX

const validateReview = (req, res, next) => {
  const { error } = reviewSchema.validate(req.body);
  if (error) {
    throw new ExpressError(
      400,
      error.details.map(e => e.message).join(", ")
    );
  }
  next();
};

// == SESSION 
app.use(
  session({
    secret: "mysupersecret",
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
  if (!req.session.user) return res.redirect("/home/login");
  next();
}

function isTeacher(req, res, next) {
  if (!req.session.user || req.session.user.role !== "teacher") {
    return res.status(403).send("Teacher access only");
  }
  next();
}

function isAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send("Admin access only");
  }
  next();
}

app.get("/resources", (req, res) => res.render("resources"));
app.get("/contact", (req, res) => res.render("contact"));
app.get("/", (req, res) => res.redirect("/home"));
app.get("/home", (req, res) => res.render("home"));
app.get("/home/aboutus", (req, res) => res.render("aboutus"));

app.get("/home/course", wrapAsync(async (req, res) => {
  const AllCourses = await Course.find({});
  res.render("course", { AllCourses });
}));

app.get("/notes", (req, res) => res.render("notes"));
app.get("/home/login", (req, res) => res.render("login"));
app.get("/home/signup", (req, res) => res.render("signup"));
app.get("/home/terms", (req, res) => res.render("terms"));
app.post("/register", wrapAsync(async (req, res) => {
  const { username, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  const user = new User({ username, email, password: hash });
  await user.save();

  req.session.user = {
    _id: user._id,
    username: user.username,
    email: user.email,
    role: user.role
  };

  res.redirect("/home");
}));

app.post("/login", wrapAsync(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) throw new ExpressError(401, "User not found");

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) throw new ExpressError(401, "Wrong password");

  req.session.user = {
    _id: user._id,
    username: user.username,
    email: user.email,
    role: user.role
  };

  res.redirect("/home");
}));

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
  user.boughtCourses.push(req.params.id);
  await user.save();

  res.redirect("/afterbuy");
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
    thumbnail: req.body.thumbnail, // ✅ FIX
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
app.use((req, res) => {
  res.status(404).render("error", { message: "Page Not Found" });
});

app.use((err, req, res, next) => {
  const { statusCode = 500, message = "Something went wrong" } = err;
  res.status(statusCode).render("error", { message });
});

// ================= SOCKET =================
const server = http.createServer(app);
const io = new Server(server);

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  socket.on("join-room", (roomId) => {
    socket.join(roomId);
    socket.to(roomId).emit("user-joined", socket.id);

    const count = io.sockets.adapter.rooms.get(roomId)?.size || 0;
    io.to(roomId).emit("user-count", count);
  });

  socket.on("offer", ({ to, offer }) => {
    io.to(to).emit("offer", { from: socket.id, offer });
  });

  socket.on("answer", ({ to, answer }) => {
    io.to(to).emit("answer", { from: socket.id, answer });
  });

  socket.on("ice-candidate", ({ to, candidate }) => {
    io.to(to).emit("ice-candidate", { from: socket.id, candidate });
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

// ================= SERVER =================
server.listen(3000, () => {
  console.log("✅ Server running on port 3000");
});
