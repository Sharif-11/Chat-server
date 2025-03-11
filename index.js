const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const bodyParser = require("body-parser");
const cors = require("cors");
const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: "*" } });

app.use(cors());
app.use(bodyParser.json());

const SECRET_KEY = process.env.JWT_SECRET || "your_secret_key";
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// Graceful DB Connection Handling
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((error) => {
    console.error("❌ MongoDB Connection Error:", error.message);
    process.exit(1);
  });

const userSchema = new mongoose.Schema({
  userId: { type: String, unique: true },
  name: String,
  password: String,
  role: { type: String, enum: ["agent", "admin"], required: true },
});

const User = mongoose.model("User", userSchema);

let chatRequests = [];
let agentPool = new Set();

/* ===================================
   ✅ Middleware for Authentication 
====================================== */
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Access denied" });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid token" });

    req.user = decoded;
    next();
  });
};

/* ===================================
   ✅ Routes for User Authentication 
====================================== */

// Create Admin
app.post("/create-admin", async (req, res) => {
  const { name, password, userId } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({
    userId,
    name,
    password: hashedPassword,
    role: "admin",
  });
  try {
    await newUser.save();
    res.json({ success: true, userId });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Create Agent
app.post("/agents", async (req, res) => {
  const { name, password, userId } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({
    userId,
    name,
    password: hashedPassword,
    role: "agent",
  });
  try {
    await newUser.save();
    res.json({
      success: true,
      message: "Agent created Successfully",
      data: userId,
    });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// User Login (Returns Access Token)
app.post("/login", async (req, res) => {
  const { agentId: userId, password } = req.body;
  const user = await User.findOne({ userId });

  if (user && (await bcrypt.compare(password, user.password))) {
    const token = jwt.sign({ userId, role: user.role }, SECRET_KEY, {
      expiresIn: "2h",
    });
    const { password, ...userWithoutPassword } = user.toObject();

    res.json({
      success: true,
      message: "Login successful",
      data: { ...userWithoutPassword, token },
    });
  } else {
    res.status(401).json({ success: false, message: "Invalid credentials" });
  }
});

// Check if User is Logged In
app.get("/check-login", authenticateToken, async (req, res) => {
  const user = await User.findOne({ userId: req.user.userId });
  if (!user) {
    return res.status(401).json({ success: false, message: "Invalid user" });
  } else {
    const { password, ...userWithoutPassword } = user.toObject();
    res.json({
      success: true,
      message: "User is logged in",
      data: userWithoutPassword,
    });
  }
});

// Logout Route
app.post("/logout", authenticateToken, (req, res) => {
  console.log("🔴 User logged out:", req.user.userId);
  agentPool.delete(req.user.userId);
  res.json({ success: true, message: "Logged out successfully" });
});

/* ===================================
   ✅ Protected Admin Routes 
====================================== */

// Only Admins Can Access This
app.get("/agents", authenticateToken, async (req, res) => {
  // if (req.user.role !== "admin") {
  //   return res.status(403).json({ message: "Unauthorized access" });
  // }
  // filter out password please
  const agents = await User.find({ role: "agent" }).select("-password");
  res.json({
    success: true,
    message: "Agent retreived successfully",
    data: agents,
  });
});

/* ===================================
   ✅ Socket.io Handling
====================================== */

io.on("connection", (socket) => {
  console.log("🔗 New client connected");

  socket.on("agent_join", ({ userId }) => {
    if (!userId) {
      return;
    }
    agentPool.add(userId);
    console.log(`✅ Agent ${userId} joined.`);
    console.log("Agent Pool:", agentPool);
  });

  socket.on("new_chat_request", (data) => {
    if (agentPool.size === 0) {
      socket.emit("no_agents_available", {
        message: "No agents are currently available. Please try again later.",
      });
      return;
    }

    chatRequests.push(data);
    io.emit("notify_agents", {
      message: `User ${data.userId} wants to talk with you.`,
    });
  });

  socket.on("accept_chat", async ({ agentId, userId }) => {
    if (!chatRequests.find((req) => req.userId === userId)) {
      socket.emit("chat_already_accepted", {
        message: "This chat request has already been accepted.",
      });
      return;
    }

    chatRequests = chatRequests.filter((req) => req.userId !== userId);
    agentPool.delete(agentId);

    const chatSession = new Chat({
      userId,
      agentId,
      messages: [],
    });
    await chatSession.save();

    activeChats.set(userId, agentId);
    io.to(agentId).emit("chat_assigned", { userId });
    io.to(userId).emit("chat_assigned", { agentId });
  });

  socket.on("send_message", async ({ userId, agentId, message, sender }) => {
    const chat = await Chat.findOne({ userId, agentId });
    if (chat) {
      chat.messages.push({ sender, message });
      await chat.save();
      io.to(userId).emit("receive_message", { sender, message });
      io.to(agentId).emit("receive_message", { sender, message });
    }
  });

  socket.on("end_chat", async ({ userId, agentId }) => {
    activeChats.delete(userId);
    agentPool.add(agentId);
    io.to(agentId).emit("chat_ended", { message: "Chat session ended." });
    io.to(userId).emit("chat_ended", { message: "Chat session ended." });
  });

  socket.on("disconnect", () => {
    console.log("❌ Client disconnected");
  });
});

/* ===================================
   ✅ Graceful Shutdown Handling 
====================================== */
const gracefulShutdown = () => {
  console.log("🔴 Shutting down server...");
  server.close(() => {
    console.log("✅ HTTP server closed.");
    mongoose.connection.close(false, () => {
      console.log("✅ MongoDB connection closed.");
      process.exit(0);
    });
  });
};

process.on("SIGINT", gracefulShutdown);
process.on("SIGTERM", gracefulShutdown);

/* ===================================
   ✅ Start Server 
====================================== */
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
