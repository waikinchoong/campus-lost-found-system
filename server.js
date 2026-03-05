const express = require("express")
const mysql = require("mysql2")
const bcrypt = require("bcrypt")
const session = require("express-session")
const helmet = require("helmet")
require("dotenv").config()

const app = express()

/* ================= SECURITY MIDDLEWARE ================= */

app.use(helmet())

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static("public"))

app.use(session({
    secret: process.env.SESSION_SECRET || "superSecretKey",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true
    }
}))

/* ================= DATABASE ================= */

const db = mysql.createConnection(process.env.DATABASE_URL)

db.connect(err => {
    if (err) {
        console.error("Database connection failed:", err)
        process.exit(1)
    }

    console.log("MySQL Connected")

    db.query(`
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    `)

    db.query(`
        CREATE TABLE IF NOT EXISTS items (
            id INT AUTO_INCREMENT PRIMARY KEY,
            category VARCHAR(100),
            type VARCHAR(50),
            title VARCHAR(255),
            description TEXT,
            location VARCHAR(255),
            date VARCHAR(100),
            contact VARCHAR(255),
            status VARCHAR(50),
            user_id INT
        )
    `)
})

/* ================= HELPERS ================= */

function requireLogin(req, res, next) {
    if (!req.session.userId)
        return res.status(401).json({ message: "Login required" })
    next()
}

function validateFields(fields) {
    return fields.every(f => f && f.trim() !== "")
}

const qiuEmailRegex = /^[a-zA-Z0-9._%+-]+@qiu\.edu\.my$/

/* ===== XSS SANITIZE ===== */

function sanitizeInput(str) {
    if (!str) return ""
    return str.replace(/<[^>]*>?/gm, "")
}

/* ================= AUTH ================= */

app.post("/signup", async (req, res) => {

    let { username, password } = req.body

    username = sanitizeInput(username)

    if (!validateFields([username, password]))
        return res.status(400).json({ message: "All fields required" })

    if (!qiuEmailRegex.test(username))
        return res.status(400).json({
            message: "Only QIU email allowed"
        })

    if (password.length < 6)
        return res.status(400).json({
            message: "Password must be at least 6 characters"
        })

    const hashed = await bcrypt.hash(password, 10)

    db.query(
        "INSERT INTO users (username,password) VALUES (?,?)",
        [username, hashed],
        err => {

            if (err)
                return res.status(400).json({
                    message: "Email already registered"
                })

            res.json({ message: "Signup success" })
        }
    )
})

app.post("/login", (req, res) => {

    let { username, password } = req.body

    username = sanitizeInput(username)

    if (!validateFields([username, password]))
        return res.status(400).json({ message: "All fields required" })

    if (!qiuEmailRegex.test(username))
        return res.status(401).json({
            message: "Invalid email domain"
        })

    db.query(
        "SELECT * FROM users WHERE username=?",
        [username],
        async (err, result) => {

            if (result.length === 0)
                return res.status(401).json({ message: "Invalid login" })

            const user = result[0]

            const match = await bcrypt.compare(password, user.password)

            if (!match)
                return res.status(401).json({ message: "Invalid login" })

            req.session.userId = user.id
            req.session.username = user.username

            res.json({ message: "Login success" })
        }
    )
})

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.json({ message: "Logged out" })
    })
})

app.get("/check-login", (req, res) => {
    res.json({
        loggedIn: !!req.session.userId,
        userId: req.session.userId || null,
        username: req.session.username || null
    })
})

/* ================= ITEMS ================= */

app.get("/items", (req, res) => {

    db.query("SELECT * FROM items", (err, result) => {

        const items = result.map(item => ({
            ...item,
            isOwner: req.session.userId === item.user_id
        }))

        res.json(items)
    })
})

app.post("/items", requireLogin, (req, res) => {

    let { category, type, title, description, location, date, contact } = req.body

    category = sanitizeInput(category)
    type = sanitizeInput(type)
    title = sanitizeInput(title)
    description = sanitizeInput(description)
    location = sanitizeInput(location)
    contact = sanitizeInput(contact)

    if (!validateFields([category, type, title, description, location, date, contact]))
        return res.status(400).json({ message: "All fields required" })

    db.query(
        `INSERT INTO items 
        (category,type,title,description,location,date,contact,status,user_id)
        VALUES (?,?,?,?,?,?,?, 'Active',?)`,
        [category, type, title, description, location, date, contact, req.session.userId],
        () => {
            res.json({ message: "Item added" })
        }
    )
})

app.put("/items/:id", requireLogin, (req, res) => {

    db.query(
        "UPDATE items SET status='Claimed' WHERE id=? AND user_id=?",
        [req.params.id, req.session.userId],
        (err, result) => {

            if (result.affectedRows === 0)
                return res.status(404).json({ message: "Not your item" })

            res.json({ message: "Updated" })
        }
    )
})

app.put("/items/edit/:id", requireLogin, (req, res) => {

    let { category, type, title, description, location, date, contact } = req.body

    category = sanitizeInput(category)
    type = sanitizeInput(type)
    title = sanitizeInput(title)
    description = sanitizeInput(description)
    location = sanitizeInput(location)
    contact = sanitizeInput(contact)

    if (!validateFields([category, type, title, description, location, date, contact]))
        return res.status(400).json({ message: "All fields required" })

    db.query(
        `UPDATE items 
         SET category=?, type=?, title=?, description=?, location=?, date=?, contact=? 
         WHERE id=? AND user_id=?`,
        [
            category,
            type,
            title,
            description,
            location,
            date,
            contact,
            req.params.id,
            req.session.userId
        ],
        (err, result) => {

            if (result.affectedRows === 0)
                return res.status(403).json({ message: "Not your item" })

            res.json({ message: "Updated" })
        }
    )
})

app.delete("/items/:id", requireLogin, (req, res) => {

    db.query(
        "DELETE FROM items WHERE id=? AND user_id=?",
        [req.params.id, req.session.userId],
        (err, result) => {

            if (result.affectedRows === 0)
                return res.status(403).json({ message: "Not your item" })

            res.json({ message: "Deleted" })
        }
    )
})

/* ================= ERRORS ================= */

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "Resource not found"
    })
})

app.use((err, req, res, next) => {
    console.error("Server Error:", err.stack)
    res.status(500).json({
        success: false,
        message: "Internal Server Error"
    })
})

/* ================= SERVER ================= */

const PORT = process.env.PORT || 3000

app.listen(PORT, () =>
    console.log("Server running on port", PORT)
)