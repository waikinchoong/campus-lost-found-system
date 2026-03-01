const express = require("express")
const mysql = require("mysql2")
const bcrypt = require("bcrypt")
const session = require("express-session")

const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static("public"))

app.use(session({
    secret: "secretKey",
    resave: false,
    saveUninitialized: false
}))

/* ================= DATABASE ================= */

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "lostfound_db"
})

db.connect(err => {
    if (err) {
        console.error("Database connection failed:", err)
        process.exit(1)
    }
    console.log("MySQL Connected")
})

/* ================= AUTH ================= */

// Signup
app.post("/signup", async (req, res, next) => {
    try {
        const { username, password } = req.body

        const hashed = await bcrypt.hash(password, 10)

        db.query(
            "INSERT INTO users (username,password) VALUES (?,?)",
            [username, hashed],
            (err) => {
                if (err)
                    return res.status(400).json({ message: "User exists" })

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
    req.session.destroy()
    res.json({ message: "Logged out" })
})

// Check login
app.get("/check-login", (req, res) => {
    res.json({
        loggedIn: !!req.session.userId,
        userId: req.session.userId || null,
        username: req.session.username || null
    })
})

function requireLogin(req, res, next) {
    if (!req.session.userId)
        return res.status(401).json({ message: "Login required" })
    next()
}

/* ================= ITEMS ================= */

// View
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

// Add
app.post("/items", requireLogin, (req, res, next) => {
    const { category, type, title, description, location, date, contact } = req.body

    db.query(
        "INSERT INTO items (category,type,title,description,location,date,contact,status,user_id) VALUES (?,?,?,?,?,?,?, 'Active',?)",
        [category,type,title,description,location,date,contact,req.session.userId],
        (err) => {
            if (err) return next(err)
            res.json({ message: "Item added" })
        }
    )
})

// Claim
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

// Edit
app.put("/items/edit/:id", requireLogin, (req, res, next) => {
    const { category, type, title, description, location, date, contact } = req.body

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

// Delete
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

app.get("/", (req,res)=>{
    res.redirect("/home.html")
})

/* ================= ERROR HANDLING ================= */

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "Resource not found"
    })
})

// Global error handler (500)
app.use((err, req, res, next) => {
    console.error("Server Error:", err.stack)

    res.status(500).json({
        success: false,
        message: "Internal Server Error"
    })
})

/* ================= SERVER ================= */

app.listen(3000, () =>
    console.log("Server running on http://localhost:3000")
)