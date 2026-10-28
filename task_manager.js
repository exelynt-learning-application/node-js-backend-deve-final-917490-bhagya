
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

const PORT = process.env.PORT || 3000;
const MONGODB_URI =
  process.env.MONGODB_URI ||
  "mongodb://127.0.0.1:27017/task_manager";

const JWT_SECRET = process.env.JWT_SECRET;

app.use(express.json({ limit: "100kb" }));

// ============================================
// 1. USER MODEL
// ============================================

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required."],
      trim: true,
      minlength: [2, "Name must contain at least 2 characters."],
      maxlength: [80, "Name cannot exceed 80 characters."]
    },
    email: {
      type: String,
      required: [true, "Email is required."],
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: 254,
      match: [
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        "Please provide a valid email address."
      ]
    },
    password: {
      type: String,
      required: [true, "Password is required."],
      minlength: [8, "Password must contain at least 8 characters."],
      select: false
    }
  },
  { timestamps: true, versionKey: false }
);

// Hash passwords before saving.
userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;

  this.password = await bcrypt.hash(this.password, 12);
});

const User = mongoose.model("User", userSchema);

// ============================================
// 2. TASK MODEL
// ============================================

const taskSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, "Task title is required."],
      trim: true,
      minlength: [2, "Title must contain at least 2 characters."],
      maxlength: [150, "Title cannot exceed 150 characters."]
    },
    description: {
      type: String,
      trim: true,
      maxlength: [2000, "Description cannot exceed 2000 characters."],
      default: ""
    },
    status: {
      type: String,
      enum: {
        values: ["Pending", "In Progress", "Completed"],
        message: "Status must be Pending, In Progress, or Completed."
      },
      default: "Pending"
    },
    priority: {
      type: String,
      enum: {
        values: ["Low", "Medium", "High"],
        message: "Priority must be Low, Medium, or High."
      },
      default: "Medium"
    },
    dueDate: {
      type: Date,
      validate: {
        validator: value => !value || !Number.isNaN(value.getTime()),
        message: "Please provide a valid due date."
      }
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    }
  },
  { timestamps: true, versionKey: false }
);

// Useful indexes for filtering and sorting.
taskSchema.index({ user: 1, status: 1, createdAt: -1 });
taskSchema.index({ user: 1, priority: 1 });

const Task = mongoose.model("Task", taskSchema);

// ============================================
// 3. ASYNC ERROR WRAPPER
// ============================================

function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// ============================================
// 4. AUTHENTICATION MIDDLEWARE
// ============================================

function authenticateToken(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Authentication required. Provide a Bearer token."
    });
  }

  const token = authorization.slice(7).trim();

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Authentication token is missing."
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = { id: decoded.sub };
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired authentication token."
    });
  }
}

// ============================================
// 5. HOME AND HEALTH ROUTES
// ============================================

app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Task Manager Backend API",
    documentation: {
      register: "POST /api/auth/register",
      login: "POST /api/auth/login",
      profile: "GET /api/auth/me",
      listTasks: "GET /api/tasks",
      createTask: "POST /api/tasks",
      getTask: "GET /api/tasks/:id",
      updateTask: "PATCH /api/tasks/:id",
      deleteTask: "DELETE /api/tasks/:id"
    }
  });
});

app.get("/health", (req, res) => {
  const connected = mongoose.connection.readyState === 1;

  res.status(connected ? 200 : 503).json({
    success: connected,
    database: connected ? "Connected" : "Disconnected"
  });
});

// ============================================
// 6. REGISTER USER
// POST /api/auth/register
// ============================================

app.post(
  "/api/auth/register",
  asyncHandler(async (req, res) => {
    const { name, email, password } = req.body || {};

    if (
      typeof password !== "string" ||
      password.length < 8 ||
      password.length > 128
    ) {
      return res.status(400).json({
        success: false,
        message: "Password must be between 8 and 128 characters."
      });
    }

    if (typeof email !== "string" || typeof name !== "string") {
      return res.status(400).json({
        success: false,
        message: "Name and email must be provided as text."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists."
      });
    }

    const user = await User.create({
      name,
      email: normalizedEmail,
      password
    });

    const token = jwt.sign(
      { sub: user._id.toString() },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.status(201).json({
      success: true,
      message: "User registered successfully.",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  })
);

// ============================================
// 7. LOGIN USER
// POST /api/auth/login
// ============================================

app.post(
  "/api/auth/login",
  asyncHandler(async (req, res) => {
    const { email, password } = req.body || {};

    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({
        success: false,
        message: "Email and password are required."
      });
    }

    const user = await User.findOne({
      email: email.trim().toLowerCase()
    }).select("+password");

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    const token = jwt.sign(
      { sub: user._id.toString() },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.status(200).json({
      success: true,
      message: "Login successful.",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  })
);

// ============================================
// 8. GET CURRENT USER
// GET /api/auth/me
// ============================================

app.get(
  "/api/auth/me",
  authenticateToken,
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User account not found."
      });
    }

    res.status(200).json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt
      }
    });
  })
);

// ============================================
// 9. CREATE TASK
// POST /api/tasks
// ============================================

app.post(
  "/api/tasks",
  authenticateToken,
  asyncHandler(async (req, res) => {
    const { title, description, status, priority, dueDate } = req.body || {};

    const task = await Task.create({
      title,
      description,
      status,
      priority,
      dueDate,
      user: req.user.id
    });

    res.status(201).json({
      success: true,
      message: "Task created successfully.",
      data: task
    });
  })
);

// ============================================
// 10. GET TASKS WITH FILTERING,
// SEARCHING AND PAGINATION
// GET /api/tasks?page=1&limit=10&status=Pending&search=report
// ============================================

app.get(
  "/api/tasks",
  authenticateToken,
  asyncHandler(async (req, res) => {
    const page = Number(req.query.page ?? 1);
    const limit = Number(req.query.limit ?? 10);

    if (
      !Number.isInteger(page) ||
      page < 1 ||
      !Number.isInteger(limit) ||
      limit < 1 ||
      limit > 100
    ) {
      return res.status(400).json({
        success: false,
        message: "Page must be positive; limit must be between 1 and 100."
      });
    }

    const filter = { user: req.user.id };

    if (req.query.status !== undefined) {
      const allowedStatuses = ["Pending", "In Progress", "Completed"];

      if (!allowedStatuses.includes(req.query.status)) {
        return res.status(400).json({
          success: false,
          message: "Invalid status filter."
        });
      }

      filter.status = req.query.status;
    }

    if (req.query.priority !== undefined) {
      const allowedPriorities = ["Low", "Medium", "High"];

      if (!allowedPriorities.includes(req.query.priority)) {
        return res.status(400).json({
          success: false,
          message: "Invalid priority filter."
        });
      }

      filter.priority = req.query.priority;
    }

    if (req.query.search !== undefined) {
      if (
        typeof req.query.search !== "string" ||
        req.query.search.length > 100
      ) {
        return res.status(400).json({
          success: false,
          message: "Search must be text with at most 100 characters."
        });
      }

      const escapedSearch = req.query.search
        .trim()
        .replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

      if (escapedSearch) {
        filter.$or = [
          { title: { $regex: escapedSearch, $options: "i" } },
          { description: { $regex: escapedSearch, $options: "i" } }
        ];
      }
    }

    const skip = (page - 1) * limit;

    const [tasks, total] = await Promise.all([
      Task.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Task.countDocuments(filter)
    ]);

    res.status(200).json({
      success: true,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      },
      count: tasks.length,
      data: tasks
    });
  })
);

// ============================================
// 11. GET TASK BY ID
// GET /api/tasks/:id
// ============================================

app.get(
  "/api/tasks/:id",
  authenticateToken,
  asyncHandler(async (req, res) => {
    if (!mongoose.isObjectIdOrHexString(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid task ID."
      });
    }

    const task = await Task.findOne({
      _id: req.params.id,
      user: req.user.id
    });

    if (!task) {
      return res.status(404).json({
        success: false,
        message: "Task not found."
      });
    }

    res.status(200).json({
      success: true,
      data: task
    });
  })
);

// ============================================
// 12. UPDATE TASK
// PATCH /api/tasks/:id
// ============================================

app.patch(
  "/api/tasks/:id",
  authenticateToken,
  asyncHandler(async (req, res) => {
    if (!mongoose.isObjectIdOrHexString(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid task ID."
      });
    }

    const allowedFields = [
      "title",
      "description",
      "status",
      "priority",
      "dueDate"
    ];

    const updates = req.body || {};
    const keys = Object.keys(updates);

    if (keys.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Provide at least one field to update."
      });
    }

    const invalidFields = keys.filter(
      key => !allowedFields.includes(key)
    );

    if (invalidFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: "Unsupported fields.",
        fields: invalidFields
      });
    }

    const task = await Task.findOneAndUpdate(
      {
        _id: req.params.id,
        user: req.user.id
      },
      { $set: updates },
      {
        new: true,
        runValidators: true
      }
    );

    if (!task) {
      return res.status(404).json({
        success: false,
        message: "Task not found."
      });
    }

    res.status(200).json({
      success: true,
      message: "Task updated successfully.",
      data: task
    });
  })
);

// ============================================
// 13. DELETE TASK
// DELETE /api/tasks/:id
// ============================================

app.delete(
  "/api/tasks/:id",
  authenticateToken,
  asyncHandler(async (req, res) => {
    if (!mongoose.isObjectIdOrHexString(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid task ID."
      });
    }

    const task = await Task.findOneAndDelete({
      _id: req.params.id,
      user: req.user.id
    });

    if (!task) {
      return res.status(404).json({
        success: false,
        message: "Task not found."
      });
    }

    res.status(200).json({
      success: true,
      message: "Task deleted successfully."
    });
  })
);

// ============================================
// 14. UNKNOWN ROUTE HANDLER
// ============================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "API endpoint not found."
  });
});

// ============================================
// 15. CENTRALIZED ERROR HANDLING
// ============================================

app.use((error, req, res, next) => {
  console.error("API error:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  if (error.type === "entity.parse.failed") {
    return res.status(400).json({
      success: false,
      message: "Invalid JSON request body."
    });
  }

  if (error.type === "entity.too.large") {
    return res.status(413).json({
      success: false,
      message: "Request body is too large."
    });
  }

  if (error.name === "ValidationError") {
    return res.status(400).json({
      success: false,
      message: "Validation failed.",
      errors: Object.values(error.errors).map(item => item.message)
    });
  }

  if (error.name === "CastError") {
    return res.status(400).json({
      success: false,
      message: "Invalid field value."
    });
  }

  if (error.code === 11000) {
    return res.status(409).json({
      success: false,
      message: "A record with this unique value already exists."
    });
  }

  res.status(500).json({
    success: false,
    message: "Internal server error."
  });
});

// ============================================
// 16. CONNECT TO DATABASE AND START SERVER
// ============================================

async function startServer() {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error(
      "Set JWT_SECRET in .env to a random secret of at least 32 characters."
    );
    process.exitCode = 1;
    return;
  }

  try {
    await mongoose.connect(MONGODB_URI);
    console.log("MongoDB connected successfully.");

    const server = app.listen(PORT, () => {
      console.log(`Task Manager API running at http://localhost:${PORT}`);
    });

    async function shutdown() {
      console.log("Shutting down server...");

      server.close(async error => {
        if (error) {
          console.error("Server shutdown error:", error.message);
          process.exitCode = 1;
        }

        try {
          await mongoose.disconnect();
          console.log("MongoDB disconnected.");
        } catch (disconnectError) {
          console.error("Database shutdown error:", disconnectError.message);
          process.exitCode = 1;
        }
      });
    }

    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  } catch (error) {
    console.error("Failed to start server:", error.message);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  startServer();
}

module.exports = { app, User, Task, startServer };
