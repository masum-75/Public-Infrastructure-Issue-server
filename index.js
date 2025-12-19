const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET);
const PDFDocument = require("pdfkit");
const admin = require("firebase-admin");
const port = process.env.PORT || 5000;

const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

app.use(express.json());
app.use(
  cors({
    origin: process.env.CLIENT_DOMAIN,
    credentials: true,
  })
);

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.1rpvn4e.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).send({ message: "unauthorized access" });
  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.decoded_email = decoded.email;
    next();
  } catch (err) {
    return res.status(401).send({ message: "unauthorized access" });
  }
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

async function run() {
  try {
    await client.connect();
    const db = client.db("issue_report_db");
    const userCollection = db.collection("users");
    const issuesCollection = db.collection("issues");
    const trackingCollection = db.collection("trackings");
    const paymentCollection = db.collection("payments");
    const upvoteCollection = db.collection("upvotes");

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

   app.get("/users/:email/role", async (req, res) => {
    try {
        const email = req.params.email;
        const user = await userCollection.findOne({ email: email.toLowerCase() });
        
        if (!user) {
            return res.send({
                role: "citizen",
                isPremium: false,
                isBlocked: false,
            });
        }

        res.send({
            role: user?.role || "citizen",
            isPremium: user?.isPremium || false,
            isBlocked: user?.isBlocked || false,
        });
    } catch (error) {
        res.status(500).send({ message: "Role error" });
    }
});

   app.post("/users", async (req, res) => {
    try {
        const user = req.body;
        
        const userEmail = user.email.toLowerCase();
        const query = { email: userEmail };
        
        const userExists = await userCollection.findOne(query);

        if (userExists) {
            return res.status(409).send({
                success: false,
                message: "User already registered.",
            });
        }

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

    app.get("/users/all", verifyFBToken, verifyAdmin, async (req, res) => {
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

    app.patch(
      "/users/:id/block",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        res.send(
          await userCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { isBlocked: req.body.isBlocked } }
          )
        );
      }
    );

    app.post("/issues", verifyFBToken, verifyBlocked, async (req, res) => {
      try {
        const issue = req.body;

        if (
          !issue.title ||
          !issue.description ||
          !issue.imageUrl ||
          !issue.category
        ) {
          return res
            .status(400)
            .send({ message: "Required fields are missing!" });
        }

        const user = await userCollection.findOne({ email: req.decoded_email });
        if (!user) return res.status(404).send({ message: "User not found" });

        if (!user.isPremium && (user.issueCount || 0) >= 3) {
          return res
            .status(403)
            .send({ message: "Free user limit reached! Please subscribe." });
        }

        issue.status = "Pending";
        issue.priority = "Normal";
        issue.upvotes = 0;
        issue.citizenEmail = req.decoded_email;
        issue.citizenName = user.displayName || "Citizen";
        issue.createdAt = new Date();
        issue.lastUpdatedAt = new Date();

        const result = await issuesCollection.insertOne(issue);

        await logTracking(
          issuesCollection,
          trackingCollection,
          result.insertedId,
          "Pending",
          "Issue Reported Successfully",
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
        console.error("Issue Post Error:", error);
        res
          .status(500)
          .send({ message: "Internal Server Error", error: error.message });
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
      const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
      if (issue.citizenEmail === userEmail)
        return res.status(403).send({ message: "Self-upvote not allowed" });
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

    app.post(
      "/subscription-checkout-session",
      verifyFBToken,
      async (req, res) => {
        const session = await stripe.checkout.sessions.create({
          line_items: [
            {
              price_data: {
                currency: "usd",
                unit_amount: req.body.cost * 100,
                product_data: { name: `Premium Subscription` },
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
      }
    );

    app.patch("/payment-success", async (req, res) => {
      try {
        const sessionId = req.query.session_id;
        if (!sessionId) {
          return res.status(400).send({ message: "Session ID missing" });
        }

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
            currency: session.currency || "usd",
            customerEmail: session.customer_email,
            type,
            paidAt: new Date(),
            metadata: session.metadata,
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
          return res.send({ success: true });
        } else {
          res.status(400).send({ message: "Payment not completed" });
        }
      } catch (error) {
        console.error("Payment Success Error:", error);
        res
          .status(500)
          .send({ message: "Server error during payment verification" });
      }
    });

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
        const categoryStats = await issuesCollection
          .aggregate([{ $group: { _id: "$category", count: { $sum: 1 } } }])
          .toArray();
        res.send({
          totalIssues,
          resolved,
          totalRevenue: rev[0]?.total || 0,
          categoryStats,
        });
      }
    );

    app.post(
      "/dashboard/admin/staff",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { email, password, displayName } = req.body;
        const userRecord = await admin
          .auth()
          .createUser({ email, password, displayName });
        res.send(
          await userCollection.insertOne({
            ...req.body,
            role: "staff",
            isPremium: false,
            createdAt: new Date(),
          })
        );
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
    app.get(
      "/dashboard/citizen-stats/:email",
      verifyFBToken,
      async (req, res) => {
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
      }
    );

    app.get("/invoices/:transactionId/pdf", verifyFBToken, async (req, res) => {
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

    // await client.db("admin").command({ ping: 1 });
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("CityCare Server is running...");
});

module.exports = app;
