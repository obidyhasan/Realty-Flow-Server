const express = require("express");
const cors = require("cors");
const app = express();
const port = process.env.PORT || 5000;
const jwt = require("jsonwebtoken");
require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

// Middleware
app.use(cors());
app.use(express.json());

// Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.0m3jt.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Collections
    const userCollection = client.db("realtyFlowDB").collection("users");
    const propertiesCollection = client
      .db("realtyFlowDB")
      .collection("properties");
    const wishlistCollection = client.db("realtyFlowDB").collection("wishlist");
    const reviewCollection = client.db("realtyFlowDB").collection("reviews");
    const makeOfferCollection = client
      .db("realtyFlowDB")
      .collection("makeOffer");

    // Verify Token Middleware
    const verifyToken = (req, res, next) => {
      if (!req?.headers?.authorization) {
        return res.status(401).send({ message: "unauthorized access" });
      }
      const token = req.headers?.authorization.split(" ")[1];
      jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decode) => {
        if (err) {
          return res.status(401).send({ message: "unauthorized access" });
        }
        req.decode = decode;
        next();
      });
    };

    // Agent Verify
    // use verify agent after verifyToken
    const verifyAgent = async (req, res, next) => {
      const email = req?.decode?.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isAgent = user?.role === "Agent";

      if (!isAgent) {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    // Admin Verify
    const verifyAdmin = async (req, res, next) => {
      const email = req?.decode?.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isAdmin = user?.role === "Admin";

      if (!isAdmin) {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    // JWT Token Create api
    app.post("/api/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.JWT_SECRET_KEY, {
        expiresIn: "30 days",
      });
      res.send({ token });
    });

    // ------------- Users Apis -------------
    // caret user api (public, user)
    app.post("/api/users", async (req, res) => {
      const userInfo = req.body;

      const query = { email: userInfo.email };
      const userExist = await userCollection.findOne(query);

      if (userExist) {
        return res.send({ message: "User already exists" });
      }

      const result = await userCollection.insertOne(userInfo);
      res.send(result);
    });

    // Get Single User (User)
    app.get("/api/user/:email", verifyToken, async (req, res) => {
      const { email } = req.params;

      if (email !== req?.decode?.email) {
        return res.status(403).send({ message: "forbidden access" });
      }

      const query = { email: email };
      const result = await userCollection.findOne(query);
      res.send(result);
    });

    // Get All user (admin access)
    app.get("/api/users", verifyToken, verifyAdmin, async (req, res) => {
      const result = await userCollection.find().toArray();
      res.send(result);
    });

    // Update User role by id (admin access)]
    app.patch(
      "/api/users/role/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const userInfo = req.body;
        const query = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            role: userInfo?.role,
          },
        };
        const result = await userCollection.updateOne(query, updateDoc);
        res.send(result);
      }
    );

    // Make user to fraud (admin access)
    app.patch(
      "/api/users/status/:email",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const { email } = req.params;
        const statusInfo = req.body;
        const query = { email: email };
        const updateDoc = {
          $set: {
            status: statusInfo.status,
          },
        };
        const filter = { "agent.email": email };
        const updateResult = await userCollection.updateOne(query, updateDoc);
        const deleteResult = await propertiesCollection.deleteMany(filter);

        res.send(updateResult);
      }
    );

    // delete user by id (admin access)
    app.delete("/api/users", verifyToken, verifyAdmin, async (req, res) => {
      const { id, uid } = req.query;
      // Delete From Database
      const query = { _id: new ObjectId(id) };
      const resultDatabase = await userCollection.deleteOne(query);

      // delete from firebase
      await admin.auth().deleteUser(uid);
      res.send(resultDatabase);
    });

    // -------------- Properties APIs ------------

    // Get all Properties for admin (admin access)
    app.get("/api/properties", verifyToken, verifyAdmin, async (req, res) => {
      const result = await propertiesCollection.find().toArray();
      res.send(result);
    });

    app.get("/api/all-properties", verifyToken, async (req, res) => {
      const { search, sort } = req.query;
      let query = {};
      query = { verificationStatus: "Verified" };

      if (search) {
        query = { ...query, location: { $regex: search, $options: "i" } };
      }

      // Sort by price
      let options = {};
      if (sort === "true") {
        options = {
          sort: { "priceRange.min": 1 },
        };
      }

      const result = await propertiesCollection.find(query, options).toArray();
      res.send(result);
    });

    // Post properties api (Agent Access)
    app.post("/api/properties", verifyToken, verifyAgent, async (req, res) => {
      const propertyInfo = req.body;
      const result = await propertiesCollection.insertOne(propertyInfo);
      res.send(result);
    });

    // Get Properties by Email (Agent Access)
    app.get(
      "/api/properties/:email",
      verifyToken,
      verifyAgent,
      async (req, res) => {
        const { email } = req.params;
        const query = { "agent.email": email };
        const result = await propertiesCollection.find(query).toArray();
        res.send(result);
      }
    );

    // Get Single property by Id
    app.get("/api/property/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const query = { _id: new ObjectId(id) };
      const result = await propertiesCollection.findOne(query);
      res.send(result);
    });

    // Update property status using id (Admin access)
    app.patch(
      "/api/property/status/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const status = req.body;
        const query = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            verificationStatus: status?.verificationStatus,
          },
        };
        const result = await propertiesCollection.updateOne(query, updateDoc);
        res.send(result);
      }
    );

    // Update property using id (agent access)
    app.patch(
      "/api/property/:id",
      verifyToken,
      verifyAgent,
      async (req, res) => {
        const { id } = req.params;
        const propertyInfo = req.body;
        const query = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            image: propertyInfo?.image,
            title: propertyInfo?.title,
            location: propertyInfo?.location,
            priceRange: propertyInfo?.priceRange,
            description: propertyInfo?.description,
          },
        };
        const result = await propertiesCollection.updateOne(query, updateDoc);
        res.send(result);
      }
    );

    // Delete Property by id (agent access)
    app.delete(
      "/api/properties/:id",
      verifyToken,
      verifyAgent,
      async (req, res) => {
        const { id } = req.params;
        const query = { _id: new ObjectId(id) };
        const result = await propertiesCollection.deleteOne(query);
        res.send(result);
      }
    );

    // ---------------------- Wishlist Collection API -------------
    // add wishlist
    app.post("/api/wishlist", verifyToken, async (req, res) => {
      const wishlistInfo = req.body;
      const result = await wishlistCollection.insertOne(wishlistInfo);
      res.send(result);
    });

    app.get("/api/wishlist/offer/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const pipeline = [
        {
          $match: { _id: new ObjectId(id) }, // Match based on user email
        },
        {
          $addFields: {
            propertyId: { $toObjectId: "$propertyId" }, // Convert propertyId to ObjectId
          },
        },
        {
          $lookup: {
            from: "properties", // Target collection
            localField: "propertyId", // Converted ObjectId field
            foreignField: "_id", // _id in properties collection
            as: "propertyDetails", // Output array
          },
        },
      ];

      const result = await wishlistCollection.aggregate(pipeline).toArray();
      res.send(result);
    });
    // get wishlist by user email (user access)
    app.get("/api/wishlist/:email", verifyToken, async (req, res) => {
      const { email } = req.params;
      if (req?.decode?.email !== email) {
        return res.status(403).send({ message: "forbidden access" });
      }

      const pipeline = [
        {
          $match: { userEmail: email }, // Match based on user email
        },
        {
          $addFields: {
            propertyId: { $toObjectId: "$propertyId" }, // Convert propertyId to ObjectId
          },
        },
        {
          $lookup: {
            from: "properties", // Target collection
            localField: "propertyId", // Converted ObjectId field
            foreignField: "_id", // _id in properties collection
            as: "propertyDetails", // Output array
          },
        },
      ];

      const result = await wishlistCollection.aggregate(pipeline).toArray();
      res.send(result);
    });

    // Delete wishlist from specific user
    app.delete("/api/wishlist/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const query = { _id: new ObjectId(id) };
      const result = await wishlistCollection.deleteOne(query);
      res.send(result);
    });

    // ------------------ Review Collection API ---------------
    // add review
    app.post("/api/reviews", verifyToken, async (req, res) => {
      const reviewInfo = req.body;
      const result = await reviewCollection.insertOne(reviewInfo);
      res.send(result);
    });

    // Get reviews for specific users
    app.get("/api/reviews/:email", verifyToken, async (req, res) => {
      const { email } = req.params;
      const query = { reviewerEmail: email };
      const result = await reviewCollection.find(query).toArray();
      res.send(result);
    });

    // ----------------- Make Offer Collection API ----------------
    // add offer
    app.post("/api/makeOffer", verifyToken, async (req, res) => {
      const offerInfo = req.body;
      const result = await makeOfferCollection.insertOne(offerInfo);
      res.send(result);
    });

    app.get("/api/makeOffer/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const query = { _id: new ObjectId(id) };
      const result = await makeOfferCollection.findOne(query);
      res.send(result);
    });

    // get offers by specific user by email
    app.get("/api/makeOffer/user/:email", verifyToken, async (req, res) => {
      const { email } = req.params;

      if (email !== req?.decode?.email) {
        return res.status(403).send({ message: "forbidden access" });
      }

      const query = { buyerEmail: email };
      const result = await makeOfferCollection.find(query).toArray();
      res.send(result);
    });

    // get offers by specific agent by email (agent access)
    app.get(
      "/api/makeOffer/agent/:email",
      verifyToken,
      verifyAgent,
      async (req, res) => {
        const { email } = req.params;
        const query = { agentEmail: email };
        const result = await makeOfferCollection.find(query).toArray();
        res.send(result);
      }
    );

    // Update offer property status by agent (agent access)
    app.patch(
      "/api/makeOffer/status/:id",
      verifyToken,
      verifyAgent,
      async (req, res) => {
        const { id } = req.params;
        const statusInfo = req.body;
        const query = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            status: statusInfo.status,
          },
        };
        const result = await makeOfferCollection.updateOne(query, updateDoc);
        res.send(result);
      }
    );

    // update offer property status whish are pending (agent access)
    app.patch(
      "/api/makeOffer/properties/:id",
      verifyToken,
      verifyAgent,
      async (req, res) => {
        const { id } = req.params;
        const { newStatus, excludedStatus } = req.body;
        const query = {
          propertyId: id,
          status: { $ne: excludedStatus },
        };

        const updateDoc = {
          $set: {
            status: newStatus,
          },
        };

        const result = await makeOfferCollection.updateMany(query, updateDoc);
        res.send(result);
      }
    );

    // update payment info
    app.patch("/api/makeOffer/payment/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const paymentInfo = req.body;
      const query = { _id: new ObjectId(id) };
      const updateInfo = {
        $set: {
          status: paymentInfo.status,
          transactionId: paymentInfo.transactionId,
        },
      };
      const result = await makeOfferCollection.updateOne(query, updateInfo);
      res.send(result);
    });

    // Get the sold properties form agent (agent access)
    app.get(
      "/api/makeOffer/sold/:email",
      verifyToken,
      verifyAgent,
      async (req, res) => {
        const { email } = req.params;
        const query = {
          agentEmail: email,
          status: "Bought",
        };
        const result = await makeOfferCollection.find(query).toArray();
        res.send(result);
      }
    );

    // ---------------------- Stripe Payment --------------------------
    app.post("/api/create-payment-intent", async (req, res) => {
      const { price } = req.body;
      const amount = parseInt(price * 100);
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amount,
        currency: "usd",
        payment_method_types: ["card"],
      });
      res.send({ clientSecret: paymentIntent.client_secret });
    });

    await client.connect();
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
run().catch(console.log);

app.get("/", (req, res) => {
  res.send("Realty Flow Server is running...");
});

app.listen(port, () => {
  console.log(`Realty Flow Server listening on port ${port}`);
});
