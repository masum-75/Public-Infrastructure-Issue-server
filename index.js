const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const { MongoClient, ServerApiVersion } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET);
const PDFDocument = require("pdfkit");
const admin = require("firebase-admin");
const port = process.env.PORT || 5000;

const serviceAccount = require("./public-issue-firebase-adminsdk.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// middleWare

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
  console.log("token", req.headers.authorization);
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }
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

  const updateDoc = {
    $set: {
      status: status,
      lastUpdatedAt: new Date(),
    },
  };
  await issuesCollection.updateOne({ _id: new ObjectId(issueId) }, updateDoc);
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
      const email = req.decoded_email;
      const query = { email };
      const user = await userCollection.findOne(query);
      if (!user || user.role !== "admin") {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    const verifyStaff = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await userCollection.findOne(query);
      if (!user || user.role !== "staff") {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    const verifyBlocked = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await userCollection.findOne(query);
      if (user && user.isBlocked) {
        return res.status(403).send({ message: "user is blocked" });
      }
      next();
    };

    app.get("/users/:email/role", async (req, res) => {
      const email = req.params.email;
      const query = { email };
      const user = await userCollection.findOne(query);
      res.send({
        role: user?.role || "citizen",
        isPremium: user?.isPremium || false,
        isBlocked: user?.isBlocked || false,
        displayName: user?.displayName,
      });
    });

    app.post("/users", async (req, res) => {
      const user = req.body;
      const email = user.email;
      const userExists = await userCollection.findOne({ email });
      if (userExists) {
        return res.send({ message: "user already exists" });
      }

      user.role = "citizen";
      user.isPremium = false;
      user.isBlocked = false;
      user.issueCount = 0;
      user.createdAt = new Date();

      const result = await userCollection.insertOne(user);
      res.send(result);
    });

    app.post("/issues", async (req, res) => {
      const issue = req.body;
      const userEmail = req.decoded_email;

      const user = await userCollection.findOne({ email: userEmail });

      if (!user.isPremium && user.issueCount >= 3) {
        return res
          .status(403)
          .send({ message: "Free user issue limit reached." });
      }

      issue.status = "Pending";
      issue.priority = "Normal";
      issue.upvotes = 0;
      issue.citizenEmail = userEmail;
      issue.createdAt = new Date();
      issue.lastUpdatedAt = new Date();

      const result = await issuesCollection.insertOne(issue);

      const issueId = result.insertedId.toString();
      await logTracking(
        issuesCollection,
        trackingCollection,
        issueId,
        "Pending",
        "Issue reported by citizen",
        "Citizen",
        user.displayName
      );

      if (!user.isPremium) {
        await userCollection.updateOne(
          { email: userEmail },
          { $inc: { issueCount: 1 } }
        );
      }

      res.send(result);
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
      const skip = (parseInt(page) - 1) * parseInt(limit);
      const query = {};

      if (search) {
        query.$or = [
          { title: { $regex: search, $options: "i" } },
          { location: { $regex: search, $options: "i" } },
        ];
      }
      if (category) {
        query.category = category;
      }
      if (status) {
        query.status = status;
      }
      if (priority) {
        query.priority = priority;
      }

      const sortOptions = { priority: -1, lastUpdatedAt: -1 };

      const issues = await issuesCollection
        .find(query)
        .sort(sortOptions)
        .skip(skip)
        .limit(parseInt(limit))
        .toArray();
      const total = await issuesCollection.countDocuments(query);

      res.send({
        issues,
        total,
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
      });
    });
    app.get("/issues/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const issue = await issuesCollection.findOne(query);

      if (!issue) {
        return res.status(404).send({ message: "Issue not found" });
      }

      let hasUpvoted = false;
      const upvoteQuery = { issueId: id, userEmail: req.decoded_email };
      const existingUpvote = await upvoteCollection.findOne(upvoteQuery);
      if (existingUpvote) {
        hasUpvoted = true;
      }

      res.send({ ...issue, hasUpvoted });
    });

    app.patch("/issues/:id/upvote", async (req, res) => {
      const id = req.params.id;
      const userEmail = req.decoded_email;

      const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
      if (!issue) {
        return res.status(404).send({ message: "Issue not found" });
      }

      if (issue.citizenEmail === userEmail) {
        return res
          .status(403)
          .send({ message: "Cannot upvote your own issue" });
      }

      const upvoteQuery = { issueId: id, userEmail };
      const existingUpvote = await upvoteCollection.findOne(upvoteQuery);

      if (existingUpvote) {
        return res.status(409).send({ message: "Already upvoted" });
      }

      const updateResult = await issuesCollection.updateOne(
        { _id: new ObjectId(id) },
        { $inc: { upvotes: 1 } }
      );

      const upvoteRecord = { issueId: id, userEmail, createdAt: new Date() };
      await upvoteCollection.insertOne(upvoteRecord);

      res.send(updateResult);
    });

    app.get("/trackings/:issueId/logs", async (req, res) => {
      const issueId = req.params.issueId;
      const query = { issueId: new ObjectId(issueId) };

      const result = await trackingCollection
        .find(query)
        .sort({ createdAt: -1 })
        .toArray();
      res.send(result);
    });
    app.post("/boost-checkout-session", async (req, res) => {
      const { issueId, title, cost } = req.body;
      const amount = parseInt(cost) * 100;

      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "usd",
              unit_amount: amount,
              product_data: {
                name: `Boost Priority for Issue: ${title}`,
              },
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        metadata: {
          issueId,
          type: "boost",
        },
        customer_email: req.decoded_email,
        success_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-cancelled`,
      });
      res.send({ url: session.url });
    });
    app.post("/subscription-checkout-session", async (req, res) => {
      const { cost } = req.body;
      const amount = parseInt(cost) * 100;
      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "usd",
              unit_amount: amount,
              product_data: {
                name: `Premium Citizen Subscription`,
              },
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        metadata: {
          userEmail: req.decoded_email,
          type: "subscription",
        },
        customer_email: req.decoded_email,
        success_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-cancelled`,
      });
      res.send({ url: session.url });
    });
    app.patch("/payment-success", async (req, res) => {
      const sessionId = req.query.session_id;
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      const transactionId = session.payment_intent;
      const type = session.metadata.type;

      const paymentExist = await paymentCollection.findOne({ transactionId });
      if (paymentExist) {
        return res.send({ message: "already exists", transactionId });
      }

      if (session.payment_status === "paid") {
        const payment = {
          amount: session.amount_total / 100,
          currency: session.currency,
          customerEmail: session.customer_email,
          transactionId,
          paymentStatus: session.payment_status,
          paidAt: new Date(),
          type,
          metadata: session.metadata,
        };

        await paymentCollection.insertOne(payment);

        if (type === "boost") {
          const issueId = session.metadata.issueId;

          const updateIssue = {
            $set: { priority: "High", lastUpdatedAt: new Date() },
          };
          await issuesCollection.updateOne(
            { _id: new ObjectId(issueId) },
            updateIssue
          );

          await logTracking(
            issuesCollection,
            trackingCollection,
            issueId,
            "Pending",
            "Issue priority boosted via payment",
            "Citizen",
            session.customer_email
          );

          return res.send({
            success: true,
            type: "boost",
            issueId,
            transactionId,
          });
        } else if (type === "subscription") {
          const userEmail = session.metadata.userEmail;

          const updateUser = {
            $set: { isPremium: true, subscriptionDate: new Date() },
          };
          await userCollection.updateOne({ email: userEmail }, updateUser);

          return res.send({
            success: true,
            type: "subscription",
            userEmail,
            transactionId,
          });
        }
      }
      return res.send({ success: false });
    });
    app.get("/dashboard/my-issues", async (req, res) => {
      const citizenEmail = req.decoded_email;
      const query = { citizenEmail };
      const { status, category } = req.query;

      if (status) {
        query.status = status;
      }
      if (category) {
        query.category = category;
      }

      const issues = await issuesCollection
        .find(query)
        .sort({ createdAt: -1 })
        .toArray();
      res.send(issues);
    });

    app.delete("/dashboard/my-issues/:id", async (req, res) => {
      const id = req.params.id;
      const userEmail = req.decoded_email;
      const query = {
        _id: new ObjectId(id),
        citizenEmail: userEmail,
        status: "Pending",
      };

      const issue = await issuesCollection.findOne(query);
      if (!issue) {
        return res
          .status(403)
          .send({
            message: "Cannot delete issue or issue status is not Pending",
          });
      }

      await trackingCollection.deleteMany({ issueId: new ObjectId(id) });
      const result = await issuesCollection.deleteOne(query);

      const user = await userCollection.findOne({ email: userEmail });
      if (user && !user.isPremium) {
        await userCollection.updateOne(
          { email: userEmail },
          { $inc: { issueCount: -1 } }
        );
      }

      res.send(result);
    });

    app.patch("/dashboard/my-issues/:id", async (req, res) => {
      const id = req.params.id;
      const userEmail = req.decoded_email;
      const updatedIssue = req.body;

      const filter = {
        _id: new ObjectId(id),
        citizenEmail: userEmail,
        status: "Pending",
      };
      const issue = await issuesCollection.findOne(filter);

      if (!issue) {
        return res
          .status(403)
          .send({
            message: "Cannot edit issue or issue status is not Pending",
          });
      }

      const updatedDoc = {
        $set: {
          ...updatedIssue,
          lastUpdatedAt: new Date(),
        },
      };

      const result = await issuesCollection.updateOne(filter, updatedDoc);

      if (result.modifiedCount > 0) {
        await logTracking(
          issuesCollection,
          trackingCollection,
          id,
          "Pending",
          "Issue information updated by citizen",
          "Citizen",
          issue.citizenName
        );
      }

      res.send(result);
    });

    app.get("/dashboard/admin/stats",verifyFBToken,verifyAdmin,async (req, res) => {
        try {
          const totalIssues = await issuesCollection.countDocuments();
          const resolvedIssues = await issuesCollection.countDocuments({
            status: "Resolved",
          });
          const pendingIssues = await issuesCollection.countDocuments({
            status: "Pending",
          });
          const rejectedIssues = await issuesCollection.countDocuments({
            status: "Rejected",
          });

          
          const revenueResult = await paymentCollection
            .aggregate([
              { $group: { _id: null, totalRevenue: { $sum: "$amount" } } },
            ])
            .toArray();
          const totalRevenue =
            revenueResult.length > 0 ? revenueResult[0].totalRevenue : 0;

         
          const categoryStats = await issuesCollection
            .aggregate([{ $group: { _id: "$category", count: { $sum: 1 } } }])
            .toArray();

       
          const latestIssues = await issuesCollection
            .find({})
            .sort({ createdAt: -1 })
            .limit(5)
            .toArray();

          
          const latestPayments = await paymentCollection
            .find({})
            .sort({ paidAt: -1 })
            .limit(5)
            .toArray();

          res.send({
            totalIssues,
            resolvedIssues,
            pendingIssues,
            rejectedIssues,
            totalRevenue,
            categoryStats,
            latestIssues,
            latestPayments,
          });
        } catch (error) {
          res
            .status(500)
            .send({
              message: "Error fetching admin stats",
              error: error.message,
            });
        }
      }
    );

    app.get("/dashboard/admin/payments",verifyFBToken, verifyAdmin,async (req, res) => {
        const payments = await paymentCollection
          .find({})
          .sort({ paidAt: -1 })
          .toArray();
        res.send(payments);
      }
    );
    app.post('/dashboard/admin/staff', verifyFBToken, verifyAdmin, async (req, res) => {
    const { email, password, displayName, phone, photoURL } = req.body;
    
   
    try {
        const userRecord = await admin.auth().createUser({
            email,
            password,
            displayName,
            photoURL: photoURL || 'https://via.placeholder.com/150', 
        });
        
        
        const staffUser = {
            email,
            displayName,
            photoURL: photoURL || 'https://via.placeholder.com/150',
            phone,
            role: 'staff',
            isPremium: false,
            isBlocked: false,
            createdAt: new Date()
        };
        const result = await userCollection.insertOne(staffUser);
        
        res.send({ insertedId: result.insertedId, firebaseUid: userRecord.uid });
    } catch (error) {
       
        if (error.code === 'auth/email-already-exists') {
             return res.status(409).send({ message: 'Email already exists in Firebase Auth.' });
        }
        res.status(500).send({ message: 'Failed to create staff account.', error: error.message });
    }
});
app.patch('/dashboard/admin/issues/:id/assign', verifyFBToken, verifyAdmin, async (req, res) => {
    const issueId = req.params.id;
    const { assignedStaffEmail, assignedStaffName } = req.body;
    const adminEmail = req.decoded_email;
    
   
    const adminUser = await userCollection.findOne({ email: adminEmail });

   
    const issue = await issuesCollection.findOne({ _id: new ObjectId(issueId) });
    if (issue.assignedStaffEmail) {
        return res.status(409).send({ message: 'Issue already assigned.' });
    }

    const updatedDoc = {
        $set: {
            assignedStaffEmail,
            assignedStaffName,
            lastUpdatedAt: new Date()
        }
    };
    const result = await issuesCollection.updateOne({ _id: new ObjectId(issueId) }, updatedDoc);

    
    if (result.modifiedCount > 0) {
        const message = `Issue assigned to Staff: ${assignedStaffName}`;
        await logTracking(issuesCollection, trackingCollection, issueId, issue.status, message, 'Admin', adminUser.displayName); // Status remains as it was (e.g., Pending)
    }

    res.send(result);
});


app.patch('/dashboard/admin/issues/:id/reject', verifyFBToken, verifyAdmin, async (req, res) => {
    const issueId = req.params.id;
    const adminEmail = req.decoded_email;

    
    const adminUser = await userCollection.findOne({ email: adminEmail });

   
    const issue = await issuesCollection.findOne({ _id: new ObjectId(issueId) });
    if (issue.status !== 'Pending') {
        return res.status(403).send({ message: 'Only Pending issues can be rejected.' });
    }

    const updatedDoc = {
        $set: {
            status: 'Rejected',
            lastUpdatedAt: new Date()
        }
    };
    const result = await issuesCollection.updateOne({ _id: new ObjectId(issueId) }, updatedDoc);

    
    if (result.modifiedCount > 0) {
        await logTracking(issuesCollection, trackingCollection, issueId, 'Rejected', 'Issue was reviewed and rejected by admin.', 'Admin', adminUser.displayName);
    }

    res.send(result);
});
    app.get("/invoices/:transactionId/pdf", verifyFBToken, async (req, res) => {
      const transactionId = req.params.transactionId;
      const userEmail = req.decoded_email;

      const payment = await paymentCollection.findOne({ transactionId });

      if (!payment) {
        return res.status(404).send({ message: "Payment record not found" });
      }

      const user = await userCollection.findOne({ email: userEmail });
      if (user.role !== "admin" && payment.customerEmail !== userEmail) {
        return res
          .status(403)
          .send({ message: "Forbidden access to this invoice" });
      }

      const doc = new PDFDocument({ size: "A4", margin: 50 });

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename=Invoice-${transactionId}.pdf`
      );

      doc.pipe(res);

      doc
        .fontSize(25)
        .fillColor("#4a4a4a")
        .text("Tax Invoice", { align: "center" })
        .moveDown();

      doc
        .fontSize(10)
        .text(`Date: ${new Date(payment.paidAt).toLocaleDateString()}`, {
          align: "right",
        });
      doc
        .text(`Transaction ID: ${transactionId}`, { align: "right" })
        .moveDown();

      doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke("#cccccc").moveDown();

      doc.fontSize(12).text("Billed To:", 50, doc.y);
      doc.text("Service Provider:", 350, doc.y).moveDown();

      doc.fontSize(10);
      doc.text(`${payment.customerEmail}`, 50, doc.y);
      doc.text("Public Infrastructure System", 350, doc.y).moveDown();

      doc.moveDown(2);

      const tableTop = doc.y;
      doc.fontSize(12).fillColor("#000000");
      doc.text("Description", 50, tableTop);
      doc.text("Amount", 450, tableTop, { width: 100, align: "right" });

      doc
        .moveTo(50, tableTop + 15)
        .lineTo(550, tableTop + 15)
        .stroke("#000000");

      const description =
        payment.type === "boost"
          ? `Issue Priority Boost for: ${payment.metadata.issueId}`
          : `Premium Citizen Subscription`;

      doc.fontSize(10).moveDown(0.5);
      doc.text(description, 50, doc.y);
      doc.text(
        `${payment.amount} ${payment.currency.toUpperCase()}`,
        450,
        doc.y,
        { width: 100, align: "right" }
      );

      doc.moveDown(2);

      doc.moveTo(400, doc.y).lineTo(550, doc.y).stroke("#000000");
      doc.moveDown(0.5);

      doc.fontSize(14).text("TOTAL:", 350, doc.y, { align: "left" });
      doc.text(
        `${payment.amount} ${payment.currency.toUpperCase()}`,
        450,
        doc.y,
        { width: 100, align: "right" }
      );

      doc.moveDown(3);

      doc
        .fontSize(10)
        .text(
          "Thank you for contributing to public infrastructure improvement.",
          50,
          doc.y,
          { align: "center", width: 500 }
        );

      doc.end();
    });

    app.get("/dashboard/admin-stats", async (req, res) => {
      const stats = {
        totalIssues: await issuesCollection.countDocuments(),
        resolvedIssues: await issuesCollection.countDocuments({
          status: "Resolved",
        }),
        pendingIssues: await issuesCollection.countDocuments({
          status: "Pending",
        }),
        rejectedIssues: await issuesCollection.countDocuments({
          status: "Rejected",
        }),
        totalPayments: await paymentCollection
          .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
          .toArray(),
      };
      res.send(stats);
    });
    app.delete('/dashboard/admin/staff/:email', verifyFBToken, verifyAdmin, async (req, res) => {
            const staffEmail = req.params.email;
            
            if (staffEmail === req.decoded_email) {
                 return res.status(403).send({ message: 'Cannot delete your own account.' });
            }

            try {
                const userRecord = await admin.auth().getUserByEmail(staffEmail);
                await admin.auth().deleteUser(userRecord.uid);

                const result = await userCollection.deleteOne({ email: staffEmail, role: 'staff' });
                
                if (result.deletedCount === 0) {
                     return res.status(404).send({ message: 'Staff user not found in database.' });
                }

                res.send({ deletedCount: result.deletedCount, message: 'Staff deleted successfully from Firebase and MongoDB.' });
            } catch (error) {
                if (error.code === 'auth/user-not-found') {
                    
                    await userCollection.deleteOne({ email: staffEmail, role: 'staff' });
                    return res.status(200).send({ message: 'User not found in Firebase, deleted from MongoDB.' });
                }
                res.status(500).send({ message: 'Failed to delete staff account.', error: error.message });
            }
        });
    app.get('/users/staff', verifyFBToken, verifyAdmin, async (req, res) => {
    const staffList = await userCollection.find({ role: 'staff' }).sort({ createdAt: -1 }).toArray();
    res.send(staffList);
});
    app.get("/users/all", verifyFBToken, verifyAdmin, async (req, res) => {
      const users = await userCollection
        .find({ role: { $ne: "admin" } })
        .sort({ createdAt: -1 })
        .toArray();
      res.send(users);
    });
    app.get('/dashboard/staff/assigned-issues', verifyFBToken, verifyStaff, async (req, res) => {
    const staffEmail = req.decoded_email;
    const { status, priority } = req.query;

    const query = { assignedStaffEmail: staffEmail };
    if (status) { query.status = status; }
    if (priority) { query.priority = priority; }
    
    
    const sortOptions = { priority: -1, lastUpdatedAt: -1 };

    const issues = await issuesCollection.find(query).sort(sortOptions).toArray();
    res.send(issues);
});

app.get('/dashboard/staff/stats', verifyFBToken, verifyStaff, async (req, res) => {
    try {
        const staffEmail = req.decoded_email;
        
        const totalAssigned = await issuesCollection.countDocuments({ assignedStaffEmail: staffEmail });
        const resolvedCount = await issuesCollection.countDocuments({ assignedStaffEmail: staffEmail, status: 'Resolved' });
        const inProgressCount = await issuesCollection.countDocuments({ assignedStaffEmail: staffEmail, status: { $in: ['In-Progress', 'Working'] } });
        
        const dailyResolved = await issuesCollection.aggregate([
            { $match: { assignedStaffEmail: staffEmail, status: "Resolved" } },
            { 
                $project: {
                    resolutionDay: { $dateToString: { format: "%Y-%m-%d", date: "$lastUpdatedAt" } }
                } 
            },
            { $group: { _id: "$resolutionDay", resolvedCount: { $sum: 1 } } },
            { $sort: { _id: -1 } },
            { $limit: 7 } 
        ]).toArray();
        
        res.send({
            totalAssigned,
            resolvedCount,
            inProgressCount,
            dailyResolved
        });
    } catch (error) {
        res.status(500).send({ message: 'Error fetching staff stats', error: error.message });
    }
});
app.patch('/dashboard/staff/issues/:id/status', verifyFBToken, verifyStaff, async (req, res) => {
    const issueId = req.params.id;
    const { newStatus, note = 'Status updated by staff.' } = req.body;
    const staffEmail = req.decoded_email;

    
    const staffUser = await userCollection.findOne({ email: staffEmail });
    
   
    const updateDoc = {
        $set: { 
            status: newStatus,
            lastUpdatedAt: new Date()
        }
    };
    const result = await issuesCollection.updateOne({ _id: new ObjectId(issueId), assignedStaffEmail: staffEmail }, updateDoc);

    
    if (result.modifiedCount > 0) {
        const message = newStatus === 'Resolved' ? 'Issue marked as resolved.' : note;
        await logTracking(issuesCollection, trackingCollection, issueId, newStatus, message, 'Staff', staffUser.displayName);
    }

    res.send(result);
});
    app.patch(
      "/users/:id/block",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const { isBlocked } = req.body;
        const query = { _id: new ObjectId(id) };
        const updatedDoc = { $set: { isBlocked } };
        const result = await userCollection.updateOne(query, updatedDoc);
        res.send(result);
      }
    );
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Public Infrastructure Issue Reporting System");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
