// ===================================================
// server.js – FINAL VERSION (100% compatible with ALL your frontend files)
// Folder Structure: (A) - models/, public/, uploads/
// ===================================================
// ===================================================
require("dotenv").config();

console.log("Cloudinary ENV:", {
  name: !!process.env.CLOUDINARY_CLOUD_NAME,
  key: !!process.env.CLOUDINARY_API_KEY,
  secret: !!process.env.CLOUDINARY_API_SECRET,
});


console.log("ENV CHECK:", {
  mongo: !!process.env.MONGODB_URI,
  email: !!process.env.EMAIL_USER,
  session: !!process.env.SESSION_SECRET,
});
// ===================================================

const express = require('express');
//const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const http = require('http');
const { Server } = require("socket.io");
const nodemailer = require("nodemailer");

// =======================
// 1. Import Models
// =======================
const User = require('./models/User.js');
const Job = require('./models/Job.js');
const Application = require('./models/Application.js');
const Contact = require('./models/Contact.js');

// ===================================================
// EMAIL TRANSPORTER (Admin Reply System)
// ===================================================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});


// =======================
// 2. App Initialization
// =======================
const app = express();
app.set("trust proxy", 1); 
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;

// =======================
// 3. Database Connection
// =======================
console.log("RAW MONGO URI >>>", process.env.MONGODB_URI);
console.log("URI LENGTH >>>", process.env.MONGODB_URI?.length);

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB error:", err.message));

// =======================
// 4. Helper Function
// =======================
const alertAndRedirect = (res, message, redirectUrl) => {
  res.send(`
        <script>
            alert(${JSON.stringify(message)});
            window.location.href = '${redirectUrl}';
        </script>
    `);
};

// =======================
// 5. Middleware
// =======================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static public folder
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'home.html'))
);

// =======================
// 6. Session Configuration
// =======================
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true, // 🔥 REQUIRED for Render
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 2,
    },
  })
);


// =======================
// 7. Multer (Resume Upload)
// =======================
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ✅ FINAL STORAGE (Render-safe)
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "joblinker_resumes",
    resource_type: "raw",   // REQUIRED for PDFs
    format: "pdf",
    public_id: (req, file) =>
      Date.now() + "-" + file.originalname.replace(/\s+/g, "_"),
  },
});

// ✅ FINAL UPLOAD
const upload = multer({
  storage,
  fileFilter: function (req, file, cb) {
    if (file.mimetype === "application/pdf") cb(null, true);
    else cb(new Error("Only PDF files are allowed"));
  },
});

// =======================
// Multer Error Handler (PDF validation)
// =======================
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err.message.includes("PDF")) {
    return alertAndRedirect(
      res,
      err.message || "Invalid file upload",
      "/student_dashboard.html"
    );
  }
  next(err);
});

// =======================
// 8. SOCKET.IO (Realtime)
// =======================
const emitCounts = async (employerId = null) => {
  try {
    const totalJobs = await Job.countDocuments();
    io.emit("jobCounts", { totalJobs });

    if (employerId) {
      const employerJobCount = await Job.countDocuments({ employerId });
      io.to(`employer_${String(employerId)}`).emit("jobCounts", {
        totalJobs,
        employerJobCount,
      });
    }
  } catch (err) {
    console.error("emitCounts error:", err);
  }
};

io.on("connection", (socket) => {
  socket.on("join", (payload) => {
    if (!payload) return;
    if (payload.employerId) {
      socket.join(`employer_${String(payload.employerId)}`);
    }
    if (payload.role === "admin") socket.join("admin");
  });

  socket.on("leave", (payload) => {
    if (!payload) return;
    if (payload.employerId) {
      socket.leave(`employer_${String(payload.employerId)}`);
    }
    if (payload.role === "admin") socket.leave("admin");
  });
});

// ===================================================
// 9. AUTH ROUTES (Student, Employer, Admin)
// ===================================================
const saltRounds = 10;

// ----------------- Student Register -----------------
app.post("/api/student/register", async (req, res) => {
  const {
    fullName,
    collegeName,
    course,
    branch,
    phoneNumber,
    email,
    password,
  } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await User.create({
      fullName,
      collegeName,
      course,
      branch,
      phoneNumber,
      email,
      password: hashedPassword,
      role: "student",
    });
    alertAndRedirect(res, "Registration successful! Please log in.", "/student_login.html");
  } catch (error) {
    let msg = "Registration failed.";
    if (error.code === 11000) msg = "Email already registered.";
    alertAndRedirect(res, msg, "/student_register.html");
  }
});

// ----------------- Student Login -----------------
app.post("/api/student/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email, role: "student" });
    if (!user) return res.json({ success: false, message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.json({ success: false, message: "Invalid credentials" });

    req.session.user = { _id: user._id, email, role: "student" };
    req.session.save(() =>
      res.json({ success: true, redirect: "/student_dashboard.html" })
    );
  } catch (err) {
    res.json({ success: false, message: "Server error" });
  }
});

// ----------------- Employer Register -----------------
app.post("/api/employer/register", async (req, res) => {
  const { companyName, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await User.create({
      companyName,
      email,
      password: hashedPassword,
      role: "employer",
    });

    alertAndRedirect(res, "Registration successful! Please log in.", "/employer_login.html");
  } catch (error) {
    let msg = "Registration failed.";
    if (error.code === 11000) msg = "Email already registered.";
    alertAndRedirect(res, msg, "/employer_register.html");
  }
});

// ----------------- Employer Login -----------------
app.post("/api/employer/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email, role: "employer" });
    if (!user) return res.json({ success: false, message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.json({ success: false, message: "Invalid credentials" });

    req.session.user = { _id: user._id, email, role: "employer" };
    res.json({ success: true, redirect: "/employer_dashboard.html" });
  } catch (err) {
    res.json({ success: false, message: "Server error" });
  }
});

// ----------------- Admin Login (JSON) -----------------
app.post("/api/admin/login", async (req, res) => {
  console.log("ADMIN LOGIN BODY:", req.body);
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email, role: "admin" });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    req.session.user = {
      _id: user._id,
      email: user.email,
      role: "admin",
    };

    req.session.save(() => {
      res.json({
        success: true,
        redirect: "/admin_dashboard.html",
      });
    });

  } catch (err) {
    console.error("Admin login error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});


// ----------------- Get Current Session User -----------------
app.get("/api/me", (req, res) => {
  res.json(req.session.user || null);
});

// ===================================================
// CONTACT FORM – Save Message
// ===================================================
app.post("/api/contact", async (req, res) => {
  const { name, email, message } = req.body;

  try {
    await Contact.create({ name, email, message });
    res.json({ success: true, message: "Message sent!" });
  } catch (err) {
    res.json({ success: false, message: "Failed to send message" });
  }
});

// ===================================================
// 10. JOB ROUTES
// ===================================================

// CREATE JOB (Employer)
app.post("/api/jobs", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "employer")
    return alertAndRedirect(res, "Login as employer first.", "/employer_login.html");

  try {
    const { title, company, course, description } = req.body;

    const job = await Job.create({
      title,
      company,
      course,
      description,
      employerId: req.session.user._id,
    });

    await emitCounts(req.session.user._id);

    alertAndRedirect(res, "Job posted successfully!", "/employer_dashboard.html");
  } catch (err) {
    alertAndRedirect(res, "Failed to post job.", "/employer_dashboard.html");
  }
});


// GET ALL JOBS (Student + Employer)
app.get("/api/jobs", async (req, res) => {
  const jobs = await Job.find().sort({ createdAt: -1 });
  res.json(jobs);
});
app.get("/api/employer/jobs", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "employer")
    return res.status(401).json({ message: "Unauthorized" });

  const jobs = await Job.find({ employerId: req.session.user._id })
                        .sort({ createdAt: -1 });
  res.json(jobs);
});

// GET JOB BY ID
app.get("/api/jobs/:id", async (req, res) => {
  try {
    const job = await Job.findById(req.params.id);
    if (!job) return res.status(404).json({ message: "Job not found" });
    res.json(job);
  } catch (err) {
    res.status(500).json({ message: "Invalid job ID" });
  }
});

// DELETE JOB (Employer)
app.delete("/api/jobs/:id", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "employer")
    return res.status(401).json({ message: "Unauthorized" });

  try {
    const job = await Job.findById(req.params.id);
    if (!job) return res.status(404).json({ message: "Not found" });

    if (String(job.employerId) !== String(req.session.user._id))
      return res.status(403).json({ message: "Forbidden" });

    await job.deleteOne();
    emitCounts(req.session.user._id);
    res.json({ message: "Job deleted" });
  } catch (err) {
    res.status(500).json({ message: "Error deleting job" });
  }
});

// ===================================================
// 11. STUDENT JOB APPLY
// ===================================================
app.post(
  "/api/apply",

  (req, res, next) => {
    if (!req.session.user || req.session.user.role !== "student") {
      return alertAndRedirect(
        res,
        "Please login as student first.",
        "/student_login.html"
      );
    }
    next();
  },

  upload.single("resume"),

  async (req, res) => {
    console.log("FILE OBJECT:", req.file);
    console.log("PDF URL:", req.file.path);


    const { jobId, fullName, phoneNumber } = req.body;

    if (!req.file) {
      return alertAndRedirect(
        res,
        "Upload a PDF resume!",
        "/student_dashboard.html"
      );
    }

    try {
      await Application.create({
        jobId,
        studentName: fullName,
        studentEmail: req.session.user.email,
        phoneNumber,
        resume: req.file.path.replace("/upload/", "/upload/fl_inline/"),
        status: "pending",
      });

      alertAndRedirect(
        res,
        "Application submitted successfully!",
        "/student_dashboard.html"
      );

    } catch (err) {
      console.error("Apply error:", err);
      alertAndRedirect(
        res,
        "Failed to submit application.",
        "/student_dashboard.html"
      );
    }
  }
);


// ===================================================
// 12. STUDENT – View Their Applications
// ===================================================
app.get("/api/student/applications", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "student")
    return res.status(401).json({ message: "Unauthorized" });

  const apps = await Application.find({
    studentEmail: req.session.user.email,
  })
    .populate("jobId")
    .sort({ appliedAt: -1 });

  res.json(apps);
});

// ===================================================
// AI-BASED STUDENT JOB RECOMMENDATION SYSTEM
// ===================================================
app.get("/api/student/recommendations", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "student") {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const student = await User.findById(req.session.user._id);

    if (!student) {
      return res.status(404).json({ message: "Student not found" });
    }

    const jobs = await Job.find();

    // AI Matching Score Formula
    const recommendations = jobs.map(job => {
      let score = 0;

      // Course match (50 points)
      if (student.course && job.course &&
          student.course.toLowerCase() === job.course.toLowerCase()) {
        score += 50;
      }

      // Branch match (30 points)
      if (student.branch && job.branch &&
          student.branch.toLowerCase() === job.branch.toLowerCase()) {
        score += 30;
      }

      // Keyword match (20 points)
      const keywords = [
        student.course?.toLowerCase(),
        student.branch?.toLowerCase(),
        student.fullName?.toLowerCase()
      ].filter(Boolean);

      keywords.forEach(kw => {
        if (job.title.toLowerCase().includes(kw)) score += 10;
        if (job.description.toLowerCase().includes(kw)) score += 10;
      });

      // Return recommended job + score
      return {
        job,
        score: Math.min(score, 100) // max 100%
      };
    });

    // Sort by highest match first
    recommendations.sort((a, b) => b.score - a.score);

    res.json(recommendations);

  } catch (err) {
    console.error("AI Recommendation Error:", err);
    res.status(500).json({ message: "Recommendation error" });
  }
});

// ===================================================
// 13. EMPLOYER – View Applications
// ===================================================
app.get("/api/applications", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "employer")
    return res.status(401).json({ message: "Unauthorized" });

  const employerId = req.session.user._id;
  const jobs = await Job.find({ employerId });
  const jobIds = jobs.map((j) => j._id);

  const applications = await Application.find({ jobId: { $in: jobIds } }).populate("jobId");

  res.json(applications);
});

// ===================================================
// 14. EMPLOYER – Update Application Status
// ===================================================
app.patch("/api/applications/:id/status", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "employer")
    return res.status(401).json({ message: "Unauthorized" });

  const { status } = req.body;

  if (!["accepted", "rejected", "pending"].includes(status))
    return res.status(400).json({ message: "Invalid status" });

  const application = await Application.findById(req.params.id).populate("jobId");

  if (!application) return res.status(404).json({ message: "Not found" });

  if (String(application.jobId.employerId) !== String(req.session.user._id))
    return res.status(403).json({ message: "Forbidden" });

  application.status = status;
  await application.save();

  io.to(`employer_${String(req.session.user._id)}`).emit("applicationUpdated", {
    applicationId: application._id,
    jobId: application.jobId._id,
    status,
    studentName: application.studentName,
    studentEmail: application.studentEmail,
  });

  io.to("admin").emit("applicationUpdated", {
    applicationId: application._id,
    status,
  });

  res.json({ message: "Status updated", application });
});

// ===================================================
// 15. ADMIN ROUTES
// ===================================================
const ensureAdmin = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(401).json({ message: "Unauthorized" });
  next();
};

// ADMIN – View Contact Messages
app.get("/api/admin/contact", ensureAdmin, async (req, res) => {
  const messages = await Contact.find().sort({ createdAt: -1 });
  res.json(messages);
});

// ADMIN – Delete Contact Message
app.delete("/api/admin/contact/:id", ensureAdmin, async (req, res) => {
  await Contact.deleteOne({ _id: req.params.id });
  res.json({ success: true });
});

app.get("/api/admin/students", ensureAdmin, async (req, res) => {
  res.json(await User.find({ role: "student" }).select("-password"));
});

app.get("/api/admin/employers", ensureAdmin, async (req, res) => {
  res.json(await User.find({ role: "employer" }).select("-password"));
});

app.get("/api/admin/jobs", ensureAdmin, async (req, res) => {
  res.json(await Job.find().populate("employerId", "companyName email"));
});

app.get("/api/admin/applications", ensureAdmin, async (req, res) => {
  res.json(await Application.find().populate("jobId"));
});

app.delete("/api/admin/jobs/:id", ensureAdmin, async (req, res) => {
  await Job.deleteOne({ _id: req.params.id });
  emitCounts();
  res.json({ message: "Job deleted" });
});

app.delete("/api/admin/users/:id", ensureAdmin, async (req, res) => {
  await User.deleteOne({ _id: req.params.id });
  res.json({ message: "User deleted" });
});

app.delete("/api/admin/applications/:id", ensureAdmin, async (req, res) => {
  await Application.deleteOne({ _id: req.params.id });
  res.json({ message: "Application deleted" });
});

// ADMIN – Reply to a contact message + send email
app.post("/api/admin/contact/reply/:id", ensureAdmin, async (req, res)=> {
  const { reply } = req.body;

  if (!reply || reply.trim() === "")
    return res.json({ success: false, message: "Reply cannot be empty" });

  const msg = await Contact.findById(req.params.id);
  if (!msg) return res.json({ success: false, message: "Message not found" });

  // Store reply in DB
  msg.reply = reply;
  msg.repliedAt = new Date();
  await msg.save();

  // Send email back to user
  try {
    await transporter.sendMail({
      from: `"Job Linker Admin" <23a51a05k3@gmail.com>`,
      to: msg.email,
      subject: "Reply from Job Linker Admin",
      html: `
        <p>Hello <b>${msg.name}</b>,</p>
        <p>Thank you for contacting Job Linker.</p>
        <p><b>Admin Reply:</b></p>
        <p>${reply}</p>
        <br>
        <p>Regards,<br>Job Linker Admin Team</p>
      `
    });

    return res.json({ success: true, message: "Reply sent via email!" });

  } catch (error) {
    console.error("Email error:", error);
    return res.json({ success: false, message: "Reply saved but email not sent." });
  }
});

// ===================================================
// 16. Start Server
// ===================================================
server.listen(PORT, () => {
  console.log(`🔥 Server running at http://localhost:${PORT}`);
  console.log(`➡️ Open http://localhost:${PORT}/home.html`);
});
