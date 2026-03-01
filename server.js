const express = require("express")
const mysql = require("mysql2")
const bcrypt = require("bcrypt")
const session = require("express-session")
require("dotenv").config()

const app = express()

/* ================= MIDDLEWARE ================= */

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static("public"))

app.use(session({
    secret: process.env.SESSION_SECRET || "superSecretKey",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true }
}))

/* ================= DATABASE ================= */

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
})

db.connect(err => {
    if (err) {
        console.error("Database connection failed:", err)
        process.exit(1)
    }
    console.log("MySQL Connected")
})

/* ================= HELPERS ================= */

function requireLogin(req, res, next) {
    if (!req.session.userId)
        return res.status(401).json({ message: "Login required" })
    next()
}

function validateFields(fields) {
    return fields.every(field => field && field.trim() !== "")
}

const qiuEmailRegex = /^[a-zA-Z0-9._%+-]+@qiu\.edu\.my$/

/* ================= AUTH ================= */

// Signup
app.post("/signup", async (req, res, next) => {
    try {
        const { username, password } = req.body

        if (!validateFields([username, password]))
            return res.status(400).json({ message: "All fields required" })

        if (!qiuEmailRegex.test(username))
            return res.status(400).json({
                message: "Only QIU email allowed (example: raymond@qiu.edu.my)"
            })

        if (password.length < 6)
            return res.status(400).json({
                message: "Password must be at least 6 characters"
            })

        const hashed = await bcrypt.hash(password, 10)

        db.query(
            "INSERT INTO users (username,password) VALUES (?,?)",
            [username, hashed],
            (err) => {
                if (err)
                    return res.status(400).json({
                        message: "Email already registered"
                    })

                res.json({ message: "Signup success" })
            }
        )

    } catch (err) {
        next(err)
    }
})

// Login
app.post("/login", (req, res, next) => {
    const { username, password } = req.body

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

            if (err) return next(err)

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

// Logout
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.json({ message: "Logged out" })
    })
})

// Check login
app.get("/check-login", (req, res) => {
    res.json({
        loggedIn: !!req.session.userId,
        userId: req.session.userId || null,
        username: req.session.username || null
    })
})

/* ================= ITEMS ================= */

app.get("/items", (req, res, next) => {
    db.query("SELECT * FROM items", (err, result) => {

        if (err) return next(err)

        const items = result.map(item => ({
            ...item,
            isOwner: req.session.userId === item.user_id
        }))

        res.json(items)
    })
})

app.post("/items", requireLogin, (req, res, next) => {

    const { category, type, title, description, location, date, contact } = req.body

    if (!validateFields([category, type, title, description, location, date, contact]))
        return res.status(400).json({ message: "All fields required" })

    db.query(
        `INSERT INTO items 
        (category,type,title,description,location,date,contact,status,user_id) 
        VALUES (?,?,?,?,?,?,?, 'Active',?)`,
        [category, type, title, description, location, date, contact, req.session.userId],
        (err) => {
            if (err) return next(err)
            res.json({ message: "Item added" })
        }
    )
})

app.put("/items/:id", requireLogin, (req, res, next) => {

    db.query(
        "UPDATE items SET status='Claimed' WHERE id=? AND user_id=?",
        [req.params.id, req.session.userId],
        (err, result) => {

            if (err) return next(err)

            if (result.affectedRows === 0)
                return res.status(403).json({ message: "Not your item" })

            res.json({ message: "Updated" })
        }
    )
})

app.put("/items/edit/:id", requireLogin, (req, res, next) => {

    const { category, type, title, description, location, date, contact } = req.body

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

            if (err) return next(err)

            if (result.affectedRows === 0)
                return res.status(403).json({ message: "Not your item" })

            res.json({ message: "Updated" })
        }
    )
})

app.delete("/items/:id", requireLogin, (req, res, next) => {

    db.query(
        "DELETE FROM items WHERE id=? AND user_id=?",
        [req.params.id, req.session.userId],
        (err, result) => {

            if (err) return next(err)

            if (result.affectedRows === 0)
                return res.status(403).json({ message: "Not your item" })

            res.json({ message: "Deleted" })
        }
    )
})

app.get("/", (req, res) => {
    res.redirect("/home.html")
})

/* ================= ERROR HANDLING ================= */

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