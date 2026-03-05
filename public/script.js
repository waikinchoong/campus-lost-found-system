const apiUrl = "/items"

const itemsDiv = document.getElementById("items")
const filterSelect = document.getElementById("filterStatus")
const searchInput = document.getElementById("searchInput")
const authButtons = document.getElementById("authButtons")

const totalItems = document.getElementById("totalItems")
const totalLost = document.getElementById("totalLost")
const totalFound = document.getElementById("totalFound")
const totalClaimed = document.getElementById("totalClaimed")

let isLoggedIn = false
let username = null

/* ================= XSS PROTECTION ================= */

function escapeHTML(str) {
    if (!str) return ""

    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
}

/* ================= LOGIN CHECK ================= */

async function checkLogin() {
    try {
        const res = await fetch("/check-login")
        const data = await res.json()

        isLoggedIn = data.loggedIn
        username = data.username

        if (authButtons) {
            if (isLoggedIn) {
                authButtons.innerHTML = `
                    <a href="add.html" class="btn btn-dark btn-sm me-2">
                        Add Item
                    </a>
                    <span class="me-2 fw-semibold">
                        Welcome, ${escapeHTML(username)}
                    </span>
                    <button class="btn btn-outline-danger btn-sm"
                        onclick="logout()">
                        Logout
                    </button>
                `
            } else {
                authButtons.innerHTML = `
                    <a href="login.html"
                        class="btn btn-outline-dark btn-sm me-2">
                        Login
                    </a>
                    <a href="signup.html"
                        class="btn btn-dark btn-sm">
                        Signup
                    </a>
                `
            }
        }
    } catch (err) {
        console.error("Login check error:", err)
    }
}

/* ================= LOAD ITEMS ================= */

async function loadItems() {

    if (!itemsDiv) return

    await checkLogin()

    try {
        const res = await fetch(apiUrl)
        const data = await res.json()

        updateDashboard(data)

        const filterValue = filterSelect?.value || "All"
        const searchValue = searchInput?.value.toLowerCase() || ""

        const filtered = data.filter(item => {

            const matchFilter =
                filterValue === "All" ||
                item.category === filterValue ||
                item.status === filterValue

            const matchSearch =
                item.title.toLowerCase().includes(searchValue)

            return matchFilter && matchSearch
        })

        /* ===== GRID START ===== */

        itemsDiv.innerHTML = `<div class="row" id="itemsGrid"></div>`
        const grid = document.getElementById("itemsGrid")

        filtered.forEach(item => {

            const formattedDate =
                item.date ? new Date(item.date).toLocaleDateString() : ""

            grid.innerHTML += `
                <div class="col-xl-3 col-lg-4 col-md-6 mb-4">
                    <div class="glass-card item-card h-100 d-flex flex-column">

                        <div class="flex-grow-1">

                            <h5 class="mb-3">${escapeHTML(item.title)}</h5>

                            <p><strong>Category:</strong> ${escapeHTML(item.category)}</p>
                            <p><strong>Type:</strong> ${escapeHTML(item.type)}</p>
                            <p><strong>Description:</strong> ${escapeHTML(item.description)}</p>
                            <p><strong>Location:</strong> ${escapeHTML(item.location)}</p>
                            <p><strong>Date:</strong> ${escapeHTML(formattedDate)}</p>
                            <p><strong>Contact:</strong> ${escapeHTML(item.contact)}</p>

                            <span class="badge ${
                                item.status === "Claimed"
                                    ? "bg-success"
                                    : item.category === "Lost"
                                    ? "bg-danger"
                                    : "bg-primary"
                            } mb-3">
                                ${escapeHTML(item.status)}
                            </span>

                        </div>

                        ${
                            isLoggedIn && item.isOwner
                            ? `
                                <div class="mt-auto pt-3">

                                    <button class="btn btn-success btn-sm me-2"
                                        ${item.status === "Claimed" ? "disabled" : ""}
                                        onclick="claimItem(${item.id})">
                                        Claim
                                    </button>

                                    <button class="btn btn-warning btn-sm me-2"
                                        onclick="editItem(${item.id})">
                                        Edit
                                    </button>

                                    <button class="btn btn-danger btn-sm"
                                        onclick="deleteItem(${item.id})">
                                        Delete
                                    </button>

                                </div>
                              `
                            : ""
                        }

                    </div>
                </div>
            `
        })

    } catch (err) {
        console.error("Load items error:", err)
    }
}

/* ================= DASHBOARD ================= */

function updateDashboard(data) {

    if (!totalItems) return

    totalItems.innerText = data.length
    totalLost.innerText = data.filter(i => i.category === "Lost").length
    totalFound.innerText = data.filter(i => i.category === "Found").length
    totalClaimed.innerText = data.filter(i => i.status === "Claimed").length
}

/* ================= ACTIONS ================= */

function editItem(id) {
    window.location.href = `edit.html?id=${id}`
}

async function claimItem(id) {
    await fetch(`${apiUrl}/${id}`, { method: "PUT" })
    loadItems()
}

async function deleteItem(id) {
    await fetch(`${apiUrl}/${id}`, { method: "DELETE" })
    loadItems()
}

async function logout() {
    await fetch("/logout")
    location.reload()
}

/* ================= FILTER EVENTS ================= */

if (filterSelect)
    filterSelect.addEventListener("change", loadItems)

if (searchInput)
    searchInput.addEventListener("input", loadItems)

/* ================= INIT ================= */

document.addEventListener("DOMContentLoaded", loadItems)