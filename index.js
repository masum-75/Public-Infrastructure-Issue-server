const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const { MongoClient, ServerApiVersion } = require("mongodb");
const stripe = require('stripe')(process.env.STRIPE_SECRET);
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
    const trackingCollection = db.collection('trackings');
    const paymentCollection = db.collection('payments');
    const upvoteCollection = db.collection('upvotes');

    app.get('/users/:email/role', async (req, res) => {
            const email = req.params.email;
            const query = { email };
            const user = await userCollection.findOne(query);
            res.send({ 
                role: user?.role || 'citizen',
                isPremium: user?.isPremium || false,
                isBlocked: user?.isBlocked || false,
                displayName: user?.displayName
            });
        });

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
        app.get('/issues/:id',  async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const issue = await issuesCollection.findOne(query);
            
            if (!issue) {
                return res.status(404).send({ message: 'Issue not found' });
            }

            let hasUpvoted = false;
            const upvoteQuery = { issueId: id, userEmail: req.decoded_email };
            const existingUpvote = await upvoteCollection.findOne(upvoteQuery);
            if (existingUpvote) {
                hasUpvoted = true;
            }

            res.send({ ...issue, hasUpvoted });
        });

        app.patch('/issues/:id/upvote', async (req, res) => {
            const id = req.params.id;
            const userEmail = req.decoded_email;
            
            const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
            if (!issue) {
                return res.status(404).send({ message: 'Issue not found' });
            }

            if (issue.citizenEmail === userEmail) {
                 return res.status(403).send({ message: 'Cannot upvote your own issue' });
            }
            
            const upvoteQuery = { issueId: id, userEmail };
            const existingUpvote = await upvoteCollection.findOne(upvoteQuery);
            
            if (existingUpvote) {
                return res.status(409).send({ message: 'Already upvoted' });
            }

           
            const updateResult = await issuesCollection.updateOne(
                { _id: new ObjectId(id) },
                { $inc: { upvotes: 1 } }
            );

            
            const upvoteRecord = { issueId: id, userEmail, createdAt: new Date() };
            await upvoteCollection.insertOne(upvoteRecord);

            res.send(updateResult);
        });

        app.get('/trackings/:issueId/logs', async (req, res) => {
            const issueId = req.params.issueId;
            const query = { issueId: new ObjectId(issueId) };
          
            const result = await trackingCollection.find(query).sort({ createdAt: -1 }).toArray(); 
            res.send(result);
        });
        app.post('/boost-checkout-session',  async (req, res) => {
            const { issueId, title, cost } = req.body;
            const amount = parseInt(cost) * 100; 

            const session = await stripe.checkout.sessions.create({
                line_items: [
                    {
                        price_data: {
                            currency: 'usd', 
                            unit_amount: amount,
                            product_data: {
                                name: `Boost Priority for Issue: ${title}`
                            }
                        },
                        quantity: 1,
                    },
                ],
                mode: 'payment',
                metadata: {
                    issueId,
                    type: 'boost'
                },
                customer_email: req.decoded_email,
                success_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-cancelled`,
            });
            res.send({ url: session.url });
        });
        app.post('/subscription-checkout-session',  async (req, res) => {
            const { cost } = req.body;
            const amount = parseInt(cost) * 100; 
            const session = await stripe.checkout.sessions.create({
                line_items: [
                    {
                        price_data: {
                            currency: 'usd',
                            unit_amount: amount,
                            product_data: {
                                name: `Premium Citizen Subscription`
                            }
                        },
                        quantity: 1,
                    },
                ],
                mode: 'payment',
                metadata: {
                    userEmail: req.decoded_email,
                    type: 'subscription'
                },
                customer_email: req.decoded_email,
                success_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-cancelled`,
            });
            res.send({ url: session.url });
        });
        app.patch('/payment-success', async (req, res) => {
            const sessionId = req.query.session_id;
            const session = await stripe.checkout.sessions.retrieve(sessionId);
            const transactionId = session.payment_intent;
            const type = session.metadata.type;

            const paymentExist = await paymentCollection.findOne({ transactionId });
            if (paymentExist) {
                return res.send({ message: 'already exists', transactionId });
            }

            if (session.payment_status === 'paid') {
                const payment = {
                    amount: session.amount_total / 100,
                    currency: session.currency,
                    customerEmail: session.customer_email,
                    transactionId,
                    paymentStatus: session.payment_status,
                    paidAt: new Date(),
                    type,
                    metadata: session.metadata
                };
                
                await paymentCollection.insertOne(payment);

                if (type === 'boost') {
                    const issueId = session.metadata.issueId;
                   
                    const updateIssue = { $set: { priority: 'High', lastUpdatedAt: new Date() } };
                    await issuesCollection.updateOne({ _id: new ObjectId(issueId) }, updateIssue);

                    
                    await logTracking(issuesCollection, trackingCollection, issueId, 'Pending', 'Issue priority boosted via payment', 'Citizen', session.customer_email);
                    
                    return res.send({ success: true, type: 'boost', issueId, transactionId });

                } else if (type === 'subscription') {
                    const userEmail = session.metadata.userEmail;
                   
                    const updateUser = { $set: { isPremium: true, subscriptionDate: new Date() } };
                    await userCollection.updateOne({ email: userEmail }, updateUser);

                    return res.send({ success: true, type: 'subscription', userEmail, transactionId });
                }
            }
            return res.send({ success: false });
        });
        app.get('/dashboard/my-issues',  async (req, res) => {
            const citizenEmail = req.decoded_email;
            const query = { citizenEmail };
            const { status, category } = req.query;

            if (status) { query.status = status; }
            if (category) { query.category = category; }

            const issues = await issuesCollection.find(query).sort({ createdAt: -1 }).toArray();
            res.send(issues);
        });

        app.delete('/dashboard/my-issues/:id',  async (req, res) => {
            const id = req.params.id;
            const userEmail = req.decoded_email;
            const query = { _id: new ObjectId(id), citizenEmail: userEmail, status: 'Pending' };

            const issue = await issuesCollection.findOne(query);
            if (!issue) {
                return res.status(403).send({ message: 'Cannot delete issue or issue status is not Pending' });
            }
            
            
            await trackingCollection.deleteMany({ issueId: new ObjectId(id) });
            const result = await issuesCollection.deleteOne(query);
            
            
            const user = await userCollection.findOne({ email: userEmail });
            if (user && !user.isPremium) {
                await userCollection.updateOne({ email: userEmail }, { $inc: { issueCount: -1 } });
            }

            res.send(result);
        });

        app.patch('/dashboard/my-issues/:id',  async (req, res) => {
            const id = req.params.id;
            const userEmail = req.decoded_email;
            const updatedIssue = req.body;
            
            const filter = { _id: new ObjectId(id), citizenEmail: userEmail, status: 'Pending' };
            const issue = await issuesCollection.findOne(filter);
            
            if (!issue) {
                return res.status(403).send({ message: 'Cannot edit issue or issue status is not Pending' });
            }

            const updatedDoc = {
                $set: {
                    ...updatedIssue,
                    lastUpdatedAt: new Date(),
                }
            };

            const result = await issuesCollection.updateOne(filter, updatedDoc);

            if (result.modifiedCount > 0) {
                await logTracking(issuesCollection, trackingCollection, id, 'Pending', 'Issue information updated by citizen', 'Citizen', issue.citizenName);
            }

            res.send(result);
        });

        app.get('/dashboard/admin-stats',  async (req, res) => {
            
            const stats = {
                totalIssues: await issuesCollection.countDocuments(),
                resolvedIssues: await issuesCollection.countDocuments({ status: 'Resolved' }),
                pendingIssues: await issuesCollection.countDocuments({ status: 'Pending' }),
                rejectedIssues: await issuesCollection.countDocuments({ status: 'Rejected' }),
                totalPayments: await paymentCollection.aggregate([
                    { $group: { _id: null, total: { $sum: '$amount' } } }
                ]).toArray()
            };
            res.send(stats);
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
