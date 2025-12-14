const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const { MongoClient, ServerApiVersion } = require("mongodb");
const port = process.env.PORT || 3000;

// middleWare

app.use(express.json());
app.use(cors());

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
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const db = client.db("issue_report_db");
    const userCollection = db.collection("users");
    const issuesCollection = db.collection('issues');

    app.post('/users', async (req, res) => {
            const user = req.body;
            const email = user.email;
            const userExists = await userCollection.findOne({ email });
            if (userExists) {
                return res.send({ message: 'user already exists' });
            }
            
            
            user.role = 'citizen';
            user.isPremium = false;
            user.isBlocked = false;
            user.issueCount = 0; 
            user.createdAt = new Date();
            
            const result = await userCollection.insertOne(user);
            res.send(result);
        });

        app.post('/issues', async (req, res) => {
            const issue = req.body;
            const userEmail = req.decoded_email;
            
            const user = await userCollection.findOne({ email: userEmail });

            if (!user.isPremium && user.issueCount >= 3) {
                return res.status(403).send({ message: 'Free user issue limit reached.' });
            }

            issue.status = 'Pending';
            issue.priority = 'Normal';
            issue.upvotes = 0;
            issue.citizenEmail = userEmail;
            issue.createdAt = new Date();
            issue.lastUpdatedAt = new Date();
            
            const result = await issuesCollection.insertOne(issue);

           
            const issueId = result.insertedId.toString();
            await logTracking(issuesCollection, trackingCollection, issueId, 'Pending', 'Issue reported by citizen', 'Citizen', user.displayName);

            
            if (!user.isPremium) {
                await userCollection.updateOne({ email: userEmail }, { $inc: { issueCount: 1 } });
            }

            res.send(result);
        });
        app.get('/issues/all', async (req, res) => {
            const { search, category, status, priority, page = 1, limit = 10 } = req.query;
            const skip = (parseInt(page) - 1) * parseInt(limit);
            const query = {};

            if (search) {
                query.$or = [
                    { title: { $regex: search, $options: 'i' } },
                    { location: { $regex: search, $options: 'i' } }
                ];
            }
            if (category) { query.category = category; }
            if (status) { query.status = status; }
            if (priority) { query.priority = priority; }
            
            
            const sortOptions = { priority: -1, lastUpdatedAt: -1 }; 

            const issues = await issuesCollection.find(query).sort(sortOptions).skip(skip).limit(parseInt(limit)).toArray();
            const total = await issuesCollection.countDocuments(query);
            
            res.send({ issues, total, currentPage: parseInt(page), totalPages: Math.ceil(total / parseInt(limit)) });
        });
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
