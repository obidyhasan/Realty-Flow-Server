const express = require("express");
const cors = require("cors");
const app = express();
const port = process.env.PORT || 5000;
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

// Middleware
app.use(cors());
app.use(express.json());

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

    // -------------- Properties APIs ------------

    // Get all Properties for admin (admin access)
    app.get("/api/properties", verifyToken, verifyAdmin, async (req, res) => {
      const result = await propertiesCollection.find().toArray();
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
