const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET);
const PDFDocument = require("pdfkit");
const admin = require("firebase-admin");

// Firebase Admin Setup

const serviceAccount = require("./public-issue-firebase-adminsdk.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

// Global Variables for Collections
let userCollection,
  issuesCollection,
  trackingCollection,
  paymentCollection,
  upvoteCollection;

// Middleware
app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:5173",],
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  })
);

// MongoDB Connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.1rpvn4e.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    const db = client.db("issue_report_db");
    userCollection = db.collection("users");
    issuesCollection = db.collection("issues");
    trackingCollection = db.collection("trackings");
    paymentCollection = db.collection("payments");
    upvoteCollection = db.collection("upvotes");
    console.log(" MongoDB Connected Successfully");
  } catch (err) {
    console.error("MongoDB Connection Error:", err);
  }
}
run().catch(console.dir);

// --- Custom Middlewares ---
const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).send({ message: "unauthorized access" });
  try {
    const idToken = token.split(" ")[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.decoded_email = decodedToken.email;
    next();
  } catch (err) {
    return res.status(401).send({ message: "unauthorized access" });
  }
};

const verifyAdmin = async (req, res, next) => {
  const user = await userCollection.findOne({ email: req.decoded_email });
  if (!user || user.role !== "admin")
    return res.status(403).send({ message: "forbidden access" });
  next();
};

const verifyStaff = async (req, res, next) => {
  const user = await userCollection.findOne({ email: req.decoded_email });
  if (!user || user.role !== "staff")
    return res.status(403).send({ message: "forbidden access" });
  next();
};

const verifyBlocked = async (req, res, next) => {
  const user = await userCollection.findOne({ email: req.decoded_email });
  if (user && user.isBlocked)
    return res.status(403).send({ message: "user is blocked" });
  next();
};

const logTracking = async (
  issuesCollection,
  trackingCollection,
  issueId,
  status,
  message,
  updatedBy,
  staffName = null
) => {
  const log = {
    issueId: new ObjectId(issueId),
    status,
    message,
    updatedBy,
    staffName,
    createdAt: new Date(),
  };
  await trackingCollection.insertOne(log);
  await issuesCollection.updateOne(
    { _id: new ObjectId(issueId) },
    { $set: { status, lastUpdatedAt: new Date() } }
  );
};

app.get("/", (req, res) => {
  res.send("CityCare Server is running...");
});

// User Registration & Role
app.post("/users", async (req, res) => {
  try {
    const user = req.body;
    const userEmail = user.email.toLowerCase();
    const existingUser = await userCollection.findOne({ email: userEmail });
    if (existingUser)
      return res
        .status(200)
        .send({ message: "User already exists", insertedId: null });

    const newUser = {
      ...user,
      email: userEmail,
      role: "citizen",
      isPremium: false,
      isBlocked: false,
      issueCount: 0,
      createdAt: new Date(),
    };
    const result = await userCollection.insertOne(newUser);
    res.status(201).send(result);
  } catch (error) {
    res.status(500).send({ message: "Server Error", error: error.message });
  }
});

app.get("/users/:email/role", async (req, res) => {
  try {
    const email = req.params.email.toLowerCase();
    const query = { email };
    const user = await userCollection.findOne(query);

    res.send({
      role: user?.role || "citizen",
      isPremium: user?.isPremium || false,
      isBlocked: user?.isBlocked || false,
    });
  } catch (error) {
    res.status(500).send({ message: "Role error" });
  }
});

app.get("/users", verifyFBToken, verifyAdmin, async (req, res) => {
  res.send(
    await userCollection
      .find({ role: { $ne: "admin" } })
      .sort({ createdAt: -1 })
      .toArray()
  );
});

app.get("/users/staff", verifyFBToken, verifyAdmin, async (req, res) => {
  res.send(
    await userCollection
      .find({ role: "staff" })
      .sort({ createdAt: -1 })
      .toArray()
  );
});

app.patch("/users/:id/block", verifyFBToken, verifyAdmin, async (req, res) => {
  res.send(
    await userCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { isBlocked: req.body.isBlocked } }
    )
  );
});

// Issues
app.post("/issues", verifyFBToken, verifyBlocked, async (req, res) => {
  try {
    const issue = req.body;
    const user = await userCollection.findOne({ email: req.decoded_email });
    if (!user.isPremium && (user.issueCount || 0) >= 3)
      return res.status(403).send({ message: "Limit reached!" });

    issue.status = "Pending";
    issue.priority = "Normal";
    issue.upvotes = 0;
    issue.citizenEmail = req.decoded_email;
    issue.createdAt = new Date();
    issue.lastUpdatedAt = new Date();

    const result = await issuesCollection.insertOne(issue);
    await logTracking(
      result.insertedId,
      "Pending",
      "Issue Reported",
      "Citizen",
      user.displayName
    );

    if (!user.isPremium) {
      await userCollection.updateOne(
        { email: req.decoded_email },
        { $inc: { issueCount: 1 } }
      );
    }
    res.status(201).send(result);
  } catch (error) {
    res.status(500).send({ message: "Error posting issue" });
  }
});

app.get("/issues/all", async (req, res) => {
  const {
    search,
    category,
    status,
    priority,
    page = 1,
    limit = 10,
  } = req.query;
  const query = {};
  if (search)
    query.$or = [
      { title: { $regex: search, $options: "i" } },
      { location: { $regex: search, $options: "i" } },
    ];
  if (category) query.category = category;
  if (status) query.status = status;
  if (priority) query.priority = priority;

  const issues = await issuesCollection
    .find(query)
    .sort({ priority: -1, lastUpdatedAt: -1 })
    .skip((page - 1) * limit)
    .limit(parseInt(limit))
    .toArray();
  const total = await issuesCollection.countDocuments(query);
  res.send({ issues, total, totalPages: Math.ceil(total / limit) });
});

app.get("/issues/:id", verifyFBToken, async (req, res) => {
  const issue = await issuesCollection.findOne({
    _id: new ObjectId(req.params.id),
  });
  const upvote = await upvoteCollection.findOne({
    issueId: req.params.id,
    userEmail: req.decoded_email,
  });
  res.send({ ...issue, hasUpvoted: !!upvote });
});

app.patch("/issues/:id/upvote", verifyFBToken, async (req, res) => {
  const id = req.params.id;
  const userEmail = req.decoded_email;
  const exists = await upvoteCollection.findOne({ issueId: id, userEmail });
  if (exists) return res.status(409).send({ message: "Already upvoted" });
  await upvoteCollection.insertOne({
    issueId: id,
    userEmail,
    createdAt: new Date(),
  });
  res.send(
    await issuesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $inc: { upvotes: 1 } }
    )
  );
});

app.get("/trackings/:issueId/logs", async (req, res) => {
  res.send(
    await trackingCollection
      .find({ issueId: new ObjectId(req.params.issueId) })
      .sort({ createdAt: -1 })
      .toArray()
  );
});

app.get(
  "/dashboard/admin/payments",
  verifyFBToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const result = await paymentCollection
        .find()
        .sort({ paidAt: -1 })
        .toArray();
      res.send(result);
    } catch (error) {
      res.status(500).send({ message: "Failed to fetch payments" });
    }
  }
);

// Payments & Stripe
app.post("/boost-checkout-session", verifyFBToken, async (req, res) => {
  const { issueId, title, cost } = req.body;
  const session = await stripe.checkout.sessions.create({
    line_items: [
      {
        price_data: {
          currency: "usd",
          unit_amount: cost * 100,
          product_data: { name: `Boost: ${title}` },
        },
        quantity: 1,
      },
    ],
    mode: "payment",
    metadata: { issueId, type: "boost" },
    customer_email: req.decoded_email,
    success_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-cancelled`,
  });
  res.send({ url: session.url });
});

app.post("/subscription-checkout-session", verifyFBToken, async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    line_items: [
      {
        price_data: {
          currency: "usd",
          unit_amount: req.body.cost * 100,
          product_data: { name: `Premium` },
        },
        quantity: 1,
      },
    ],
    mode: "payment",
    metadata: { userEmail: req.decoded_email, type: "subscription" },
    customer_email: req.decoded_email,
    success_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-cancelled`,
  });
  res.send({ url: session.url });
});

app.patch("/payment-success", async (req, res) => {
  const sessionId = req.query.session_id;
  const session = await stripe.checkout.sessions.retrieve(sessionId);
  const { type, issueId, userEmail } = session.metadata;

  if (session.payment_status === "paid") {
    const alreadyExists = await paymentCollection.findOne({
      transactionId: session.payment_intent,
    });
    if (alreadyExists) return res.send({ success: true });

    await paymentCollection.insertOne({
      transactionId: session.payment_intent,
      amount: session.amount_total / 100,
      customerEmail: session.customer_email,
      type,
      paidAt: new Date(),
    });

    if (type === "boost") {
      await issuesCollection.updateOne(
        { _id: new ObjectId(issueId) },
        { $set: { priority: "High" } }
      );
    } else if (type === "subscription") {
      await userCollection.updateOne(
        { email: userEmail },
        { $set: { isPremium: true, subscriptionDate: new Date() } }
      );
    }
    res.send({ success: true });
  }
});

// Admin Stats
app.get("/dashboard/my-issues", verifyFBToken, async (req, res) => {
  const query = { citizenEmail: req.decoded_email };
  if (req.query.status) query.status = req.query.status;
  res.send(
    await issuesCollection.find(query).sort({ createdAt: -1 }).toArray()
  );
});

app.patch("/dashboard/my-issues/:id", verifyFBToken, async (req, res) => {
  const filter = {
    _id: new ObjectId(req.params.id),
    citizenEmail: req.decoded_email,
    status: "Pending",
  };
  const issue = await issuesCollection.findOne(filter);
  if (!issue) return res.status(403).send({ message: "Cannot edit" });
  const result = await issuesCollection.updateOne(filter, {
    $set: { ...req.body, lastUpdatedAt: new Date() },
  });
  if (result.modifiedCount > 0)
    await logTracking(
      issuesCollection,
      trackingCollection,
      req.params.id,
      "Pending",
      "Updated by citizen",
      "Citizen",
      issue.citizenName
    );
  res.send(result);
});

app.delete("/dashboard/my-issues/:id", verifyFBToken, async (req, res) => {
  const filter = {
    _id: new ObjectId(req.params.id),
    citizenEmail: req.decoded_email,
    status: "Pending",
  };
  const result = await issuesCollection.deleteOne(filter);
  if (result.deletedCount > 0) {
    await trackingCollection.deleteMany({
      issueId: new ObjectId(req.params.id),
    });
    await userCollection.updateOne(
      { email: req.decoded_email },
      { $inc: { issueCount: -1 } }
    );
  }
  res.send(result);
});
app.get(
  "/dashboard/admin/stats",
  verifyFBToken,
  verifyAdmin,
  async (req, res) => {
    const totalIssues = await issuesCollection.countDocuments();
    const resolved = await issuesCollection.countDocuments({
      status: "Resolved",
    });
    const rev = await paymentCollection
      .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
      .toArray();
    res.send({ totalIssues, resolved, totalRevenue: rev[0]?.total || 0 });
  }
);
app.delete(
  "/dashboard/admin/staff/:email",
  verifyFBToken,
  verifyAdmin,
  async (req, res) => {
    const staffEmail = req.params.email;
    const userRecord = await admin.auth().getUserByEmail(staffEmail);
    await admin.auth().deleteUser(userRecord.uid);
    res.send(
      await userCollection.deleteOne({ email: staffEmail, role: "staff" })
    );
  }
);
// Staff Assignment
app.patch(
  "/dashboard/admin/issues/:id/assign",
  verifyFBToken,
  verifyAdmin,
  async (req, res) => {
    const { assignedStaffEmail, assignedStaffName } = req.body;
    const adminUser = await userCollection.findOne({
      email: req.decoded_email,
    });
    const result = await issuesCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      {
        $set: {
          assignedStaffEmail,
          assignedStaffName,
          lastUpdatedAt: new Date(),
        },
      }
    );
    if (result.modifiedCount > 0)
      await logTracking(
        issuesCollection,
        trackingCollection,
        req.params.id,
        "Pending",
        `Assigned to ${assignedStaffName}`,
        "Admin",
        adminUser.displayName
      );
    res.send(result);
  }
);

app.patch(
  "/dashboard/admin/issues/:id/reject",
  verifyFBToken,
  verifyAdmin,
  async (req, res) => {
    const adminUser = await userCollection.findOne({
      email: req.decoded_email,
    });
    const result = await issuesCollection.updateOne(
      { _id: new ObjectId(req.params.id), status: "Pending" },
      { $set: { status: "Rejected", lastUpdatedAt: new Date() } }
    );
    if (result.modifiedCount > 0)
      await logTracking(
        issuesCollection,
        trackingCollection,
        req.params.id,
        "Rejected",
        "Rejected by admin",
        "Admin",
        adminUser.displayName
      );
    res.send(result);
  }
);

app.get(
  "/dashboard/staff/assigned-issues",
  verifyFBToken,
  verifyStaff,
  async (req, res) => {
    res.send(
      await issuesCollection
        .find({ assignedStaffEmail: req.decoded_email })
        .sort({ priority: -1 })
        .toArray()
    );
  }
);

app.get(
  "/dashboard/staff/stats",
  verifyFBToken,
  verifyStaff,
  async (req, res) => {
    const email = req.decoded_email;
    const totalAssigned = await issuesCollection.countDocuments({
      assignedStaffEmail: email,
    });
    const resolvedCount = await issuesCollection.countDocuments({
      assignedStaffEmail: email,
      status: "Resolved",
    });
    res.send({ totalAssigned, resolvedCount });
  }
);

app.patch(
  "/dashboard/staff/issues/:id/status",
  verifyFBToken,
  verifyStaff,
  async (req, res) => {
    const { newStatus, note } = req.body;
    const staff = await userCollection.findOne({
      email: req.decoded_email,
    });
    const result = await issuesCollection.updateOne(
      {
        _id: new ObjectId(req.params.id),
        assignedStaffEmail: req.decoded_email,
      },
      { $set: { status: newStatus, lastUpdatedAt: new Date() } }
    );
    if (result.modifiedCount > 0)
      await logTracking(
        issuesCollection,
        trackingCollection,
        req.params.id,
        newStatus,
        note,
        "Staff",
        staff.displayName
      );
    res.send(result);
  }
);
app.get("/dashboard/citizen-stats/:email", verifyFBToken, async (req, res) => {
  const email = req.params.email;
  const totalIssues = await issuesCollection.countDocuments({
    citizenEmail: email,
  });
  const resolvedIssues = await issuesCollection.countDocuments({
    citizenEmail: email,
    status: "Resolved",
  });
  const pendingIssues = await issuesCollection.countDocuments({
    citizenEmail: email,
    status: "Pending",
  });

  res.send({ totalIssues, resolvedIssues, pendingIssues });
});

app.get("/invoices/:transactionId/pdf", async (req, res) => {
  const payment = await paymentCollection.findOne({
    transactionId: req.params.transactionId,
  });
  if (!payment) return res.status(404).send("Not found");
  const doc = new PDFDocument();
  res.setHeader("Content-Type", "application/pdf");
  doc.pipe(res);
  doc.fontSize(20).text("Invoice", { align: "center" }).moveDown();
  doc
    .fontSize(12)
    .text(`Transaction: ${payment.transactionId}`)
    .text(`Amount: ${payment.amount} USD`)
    .text(`Date: ${new Date(payment.paidAt).toLocaleDateString()}`);
  doc.end();
});

// Vercel export
module.exports = app;
const port = process.env.PORT || 5000;
if (process.env.NODE_ENV !== "production") {
  app.listen(port, () => console.log(`Server running on port ${port}`));
}
