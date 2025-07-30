const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

dotenv.config();
const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// DB connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.SECRET_PASSWORD}@cluster0.1mv6arg.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_here';

//  Middleware to verify token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(403).send({ message: "No token provided" });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: "Invalid token" });

    req.user = decoded;
    next();
  });
};

async function run() {
  try {
    await client.connect();

  
    const taskCollection = client.db("taskcollection").collection("alltasks");
    const authuserCollection = client.db("authcollection").collection("authusers");

    //  Signup
    app.post('/signup', [
      body('email').isEmail(),
      body('password').isLength({ min: 6 }),
    ], async (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { name, email, password } = req.body;
      const existingUser = await authuserCollection.findOne({ email });
      if (existingUser) return res.status(400).send({ message: "User already exists" });

      const hashedPassword = await bcrypt.hash(password, 10);
      const result = await authuserCollection.insertOne({ name, email, password: hashedPassword });
      res.send({ message: "Signup successful", result });
      // console.log("User signed up successfully:", result);
      
    });

    //  Login
    app.post('/login', async (req, res) => {
      const { email, password } = req.body;
      const user = await authuserCollection.findOne({ email });
      if (!user) return res.status(401).send({ message: 'User not found' });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).send({ message: 'Invalid password' });

      // JWT Token
      const token = jwt.sign({ email: user.email, id: user._id }, JWT_SECRET, { expiresIn: '2d' });
      res.send({ message: 'Login successful', token, user: { email: user.email, name: user.name } });
    });

    //  Get all tasks (protected route)
  // Get all tasks
app.get('/alltask', verifyToken, async (req, res) => {
  const result = await taskCollection.find().toArray();
  res.send(result);
});

app.get('/tasks/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  try {
    const task = await taskCollection.findOne({ _id: new ObjectId(id) });
    if (!task) return res.status(404).send({ message: "Task not found" });
    res.send(task);
  } catch (error) {
    res.status.send({ message: "Internal server error" });
  }
});

    // Add new task (protected route)
    app.post('/task', verifyToken, async (req, res) => {
      const task = req.body;
      const result = await taskCollection.insertOne(task);
      res.send(result);
      // console.log("Task added successfully:", result);
      
    });

    // Delete task by ID (protected route)
app.delete('/alltask/:id', verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    const result = await taskCollection.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 1) {
      res.send({ message: "Task deleted successfully", deletedCount: 1 });
    } else {
      res.status.send({ message: "Task not found", deletedCount: 0 });
    }
  } catch (error) {
    console.error("Delete task error:", error);
    res.status.send({ message: "Internal server error" });
  }
});
// Update task status to "complete"
app.patch("/tasks/:id/status", async (req, res) => {
  const { id } = req.params;

  try {
    const result = await taskCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status: "complete" } }
    );

    if (result.modifiedCount === 1) {
      res.status(200).send({ message: "Task marked as complete." });
    } else {
      res.status(404).send({ message: "Task not found or already complete." });
    }
  } catch (error) {
    console.error("Error updating task status:", error);
    res.status(500).send({ message: "Internal server error." });
  }
});



    //  Ping test
    // await client.db("admin").command({ ping: 1 });
    console.log("Connected to MongoDB successfully");
  } catch (err) {
    console.error("Mongo Error:", err);
  }
}
run().catch(console.dir);

// Root route
app.get('/', (req, res) => {
  res.send('Task Server Ready ');
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
