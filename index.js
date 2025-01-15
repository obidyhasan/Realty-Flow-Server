const express = require("express");
const cors = require("cors");
const app = express();
const port = process.env.PORT || 5000;
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { MongoClient, ServerApiVersion } = require("mongodb");

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

    // JWT Token Create api
    app.post("/api/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.JWT_SECRET_KEY, {
        expiresIn: "30 days",
      });
      res.send({ token });
    });

    // ------------- Users Apis -------------
    // caret user api
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

    // Get Single User
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
    // Post properties api (Agent Access)
    app.post("/api/properties", verifyToken, async (req, res) => {
      const propertyInfo = req.body;
      const result = await propertiesCollection.insertOne(propertyInfo);
      res.send(result);
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
