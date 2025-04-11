require("dotenv").config({ path: "./.env" });

const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.ADMIN_PORT || 5001; // Different port for admin server

app.use(cors());
app.use(express.json());

const uri = process.env.MONGO_URI;
if (!uri) {
    console.error("❌ MONGO_URI is not defined in .env file");
    process.exit(1);
}

const client = new MongoClient(uri);
let db, usersCollection, menuCollection, tableCollection, eventCollection, cartCollection, orderCollection, offerCollection;
const verificationCodes = {};

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

async function connectDB() {
    try {
        await client.connect();
        db = client.db("RMS");
        usersCollection = db.collection("users");
        menuCollection = db.collection("menu");
        tableCollection = db.collection("tables");
        eventCollection = db.collection("eventHalls");
        cartCollection = db.collection("carts");
        orderCollection = db.collection("orders");
        offerCollection = db.collection("offers");
        console.log("✅ MongoDB is connected");
    } catch (err) {
        console.error("❌ DB Connection Error:", err);
        process.exit(1);
    }
}
connectDB();

// Middleware to check if user is admin
const isAdmin = async (req, res, next) => {
    const email = req.headers["x-admin-email"] || req.query.email || req.body.email; // Check headers, query, or body
    if (!email) {
        return res.status(403).json({ message: "Access denied. Admin email is required." });
    }
    const user = await usersCollection.findOne({ email });
    if (!user || !user.isAdmin) {
        return res.status(403).json({ message: "Access denied. Admin only." });
    }
    req.user = user; // Attach user to request for later use if needed
    next();
};

// Admin Signup Route
app.post("/admin/signup", async (req, res) => {
    const { name, email, phone, password, adminCode } = req.body;

    // Simple admin code check (replace with a secure method in production)
    const SECRET_ADMIN_CODE = process.env.ADMIN_CODE || "ADMIN123";
    if (adminCode !== SECRET_ADMIN_CODE) {
        return res.status(403).json({ message: "Invalid admin code." });
    }

    if (!name || !email || !phone || !password) {
        return res.status(400).json({ message: "All fields are required." });
    }

    const existing = await usersCollection.findOne({ email });
    if (existing) {
        return res.status(400).json({ message: "User already exists." });
    }

    const hashed = await bcrypt.hash(password, 10);
    const adminUser = {
        name,
        email,
        phone,
        password: hashed,
        isAdmin: true // Set admin flag
    };

    try {
        await usersCollection.insertOne(adminUser);
        res.json({ message: "Admin registered successfully." });
    } catch (err) {
        console.error("Error registering admin:", err);
        res.status(500).json({ message: "Server error during signup." });
    }
});

// Admin Login Route
app.post("/admin/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found." });
    if (!user.isAdmin) return res.status(403).json({ message: "Not an admin." });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Incorrect password." });
    res.json({ message: "Admin login successful!", email: user.email, name: user.name });
});

// Admin OTP & Password Reset Routes
app.post("/admin/forgot", async (req, res) => {
    const { email } = req.body;
    const user = await usersCollection.findOne({ email });
    if (!user || !user.isAdmin) return res.status(404).json({ message: "Admin email not found." });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    verificationCodes[email] = code;
    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Admin Password Reset Code",
        text: `Your password reset code is: ${code}`,
    });
    res.json({ message: "Verification code sent." });
});

app.post("/admin/change-password", async (req, res) => {
    const { email, code, newPassword } = req.body;
    if (verificationCodes[email] !== code) {
        return res.status(400).json({ message: "Invalid or expired code." });
    }
    const hashed = await bcrypt.hash(newPassword, 10);
    await usersCollection.updateOne({ email, isAdmin: true }, { $set: { password: hashed } });
    delete verificationCodes[email];
    res.json({ message: "Password reset successful." });
});

// Admin Menu Routes
app.post("/admin/menu/add", isAdmin, async (req, res) => {
    const { name, category, price, image } = req.body;
    if (!name || !category || !price) {
        return res.status(400).json({ message: "Missing required fields." });
    }
    const menuItem = { name, category, price: `₹${parseFloat(price).toFixed(2)}`, image: image || "" };
    try {
        await menuCollection.insertOne(menuItem);
        res.json({ message: "Menu item added successfully." });
    } catch (err) {
        console.error("Error adding menu item:", err);
        res.status(500).json({ message: "Server error adding menu item." });
    }
});

app.put("/admin/menu/update/:id", isAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, category, price, image } = req.body;
    const updateFields = {};
    if (name) updateFields.name = name;
    if (category) updateFields.category = category;
    if (price) updateFields.price = `₹${parseFloat(price).toFixed(2)}`;
    if (image) updateFields.image = image;

    try {
        const result = await menuCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateFields }
        );
        if (result.modifiedCount === 0) {
            return res.status(404).json({ message: "Menu item not found or no changes made." });
        }
        res.json({ message: "Menu item updated successfully." });
    } catch (err) {
        console.error("Error updating menu item:", err);
        res.status(500).json({ message: "Server error updating menu item." });
    }
});

app.delete("/admin/menu/delete/:id", isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await menuCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: "Menu item not found." });
        }
        res.json({ message: "Menu item deleted successfully." });
    } catch (err) {
        console.error("Error deleting menu item:", err);
        res.status(500).json({ message: "Server error deleting menu item." });
    }
});

// Admin Table Routes
app.post("/admin/tables/add", isAdmin, async (req, res) => {
    const { name, pricePerHour, available } = req.body;
    if (!name || !pricePerHour) {
        return res.status(400).json({ message: "Missing required fields." });
    }
    const table = {
        name,
        pricePerHour: parseFloat(pricePerHour),
        available: available !== undefined ? available : true
    };
    try {
        await tableCollection.insertOne(table);
        res.json({ message: "Table added successfully." });
    } catch (err) {
        console.error("Error adding table:", err);
        res.status(500).json({ message: "Server error adding table." });
    }
});

app.put("/admin/tables/update/:id", isAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, pricePerHour, available } = req.body;
    const updateFields = {};
    if (name) updateFields.name = name;
    if (pricePerHour) updateFields.pricePerHour = parseFloat(pricePerHour);
    if (available !== undefined) updateFields.available = available;

    try {
        const result = await tableCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateFields }
        );
        if (result.modifiedCount === 0) {
            return res.status(404).json({ message: "Table not found or no changes made." });
        }
        res.json({ message: "Table updated successfully." });
    } catch (err) {
        console.error("Error updating table:", err);
        res.status(500).json({ message: "Server error updating table." });
    }
});

app.delete("/admin/tables/delete/:id", isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await tableCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: "Table not found." });
        }
        res.json({ message: "Table deleted successfully." });
    } catch (err) {
        console.error("Error deleting table:", err);
        res.status(500).json({ message: "Server error deleting table." });
    }
});

// Admin Event Hall Routes
app.post("/admin/eventhalls/add", isAdmin, async (req, res) => {
    const { name, capacity, pricePerHour, available } = req.body;
    if (!name || !capacity || !pricePerHour) {
        return res.status(400).json({ message: "Missing required fields." });
    }
    const eventHall = {
        name,
        capacity: parseInt(capacity),
        pricePerHour: parseFloat(pricePerHour),
        available: available !== undefined ? available : true
    };
    try {
        await eventCollection.insertOne(eventHall);
        res.json({ message: "Event hall added successfully." });
    } catch (err) {
        console.error("Error adding event hall:", err);
        res.status(500).json({ message: "Server error adding event hall." });
    }
});

app.put("/admin/eventhalls/update/:id", isAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, capacity, pricePerHour, available } = req.body;
    const updateFields = {};
    if (name) updateFields.name = name;
    if (capacity) updateFields.capacity = parseInt(capacity);
    if (pricePerHour) updateFields.pricePerHour = parseFloat(pricePerHour);
    if (available !== undefined) updateFields.available = available;

    try {
        const result = await eventCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateFields }
        );
        if (result.modifiedCount === 0) {
            return res.status(404).json({ message: "Event hall not found or no changes made." });
        }
        res.json({ message: "Event hall updated successfully." });
    } catch (err) {
        console.error("Error updating event hall:", err);
        res.status(500).json({ message: "Server error updating event hall." });
    }
});

app.delete("/admin/eventhalls/delete/:id", isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await eventCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: "Event hall not found." });
        }
        res.json({ message: "Event hall deleted successfully." });
    } catch (err) {
        console.error("Error deleting event hall:", err);
        res.status(500).json({ message: "Server error deleting event hall." });
    }
});

// Admin Offer Routes
app.post("/admin/offers/add", isAdmin, async (req, res) => {
    const { itemId, offerPrice } = req.body;
    if (!itemId || !offerPrice) {
        return res.status(400).json({ message: "Missing required fields." });
    }

    try {
        const menuItem = await menuCollection.findOne({ _id: new ObjectId(itemId) });
        if (!menuItem) {
            return res.status(404).json({ message: "Menu item not found." });
        }

        const offer = {
            itemId: new ObjectId(itemId),
            itemName: menuItem.name,
            originalPrice: menuItem.price,
            offerPrice: parseFloat(offerPrice),
            createdAt: new Date()
        };
        await offerCollection.insertOne(offer);
        res.json({ message: "Offer added successfully." });
    } catch (err) {
        console.error("Error adding offer:", err);
        res.status(500).json({ message: "Server error adding offer." });
    }
});

app.put("/admin/offers/update/:id", isAdmin, async (req, res) => {
    const { id } = req.params;
    const { offerPrice } = req.body;
    if (!offerPrice) {
        return res.status(400).json({ message: "Offer price is required." });
    }

    try {
        const result = await offerCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { offerPrice: parseFloat(offerPrice), updatedAt: new Date() } }
        );
        if (result.modifiedCount === 0) {
            return res.status(404).json({ message: "Offer not found or no changes made." });
        }
        res.json({ message: "Offer updated successfully." });
    } catch (err) {
        console.error("Error updating offer:", err);
        res.status(500).json({ message: "Server error updating offer." });
    }
});

app.delete("/admin/offers/delete/:id", isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await offerCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: "Offer not found." });
        }
        res.json({ message: "Offer deleted successfully." });
    } catch (err) {
        console.error("Error deleting offer:", err);
        res.status(500).json({ message: "Server error deleting offer." });
    }
});

app.get("/admin/offers", isAdmin, async (req, res) => {
    try {
        const offers = await offerCollection.find().toArray();
        res.json(offers);
    } catch (err) {
        console.error("Error fetching offers:", err);
        res.status(500).json({ message: "Server error fetching offers." });
    }
});

// Admin Logout Route
app.post("/admin/logout", (req, res) => {
    res.json({ message: "Admin logout successful." });
});

// Start Server
app.listen(PORT, () => {
    console.log(`🚀 Admin Server running on port ${PORT}`);
});