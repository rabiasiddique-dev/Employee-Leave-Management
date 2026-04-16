<div align="center">
  <h1>🏢 Employee Leave Management System</h1>
  <p>A comprehensive, responsive, and easy-to-use Leave Management System built with Flask and MongoDB.</p>
</div>

<br />

![Python](https://img.shields.io/badge/Python-3.13+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-lightgrey.svg)
![MongoDB](https://img.shields.io/badge/MongoDB-NoSQL-green.svg)
![Vercel](https://img.shields.io/badge/Vercel-Deployment-black.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

---

## 🌟 Overview

The **Employee Leave Management System** is designed to streamline the process of requesting, approving, and tracking employee leaves. It provides dedicated portals for both **Employees** and **Administrators** to simplify human resource workflows and ensure accurate leave balance tracking.

## ✨ Key Features

### 👤 Employee Portal
- **Dashboard:** Overview of available leave balances (Annual, Sick, Casual, etc.) and upcoming holidays.
- **Apply for Leave:** Seamlessly submit leave requests with specific dates and reasons.
- **Leave History:** Track the status of active and historical leave applications.
- **Notifications:** Receive instant updates when a leave is approved or rejected by the admin.

### 👑 Admin Portal
- **Dashboard Overview:** Monitor total employees, pending leave requests, and department trends.
- **Leave Management:** Approve or reject employee leaves seamlessly.
- **Employee Management:** Add, edit, deactivate, or manage employee roles.
- **System Settings:** Configure default leave policies and organizational settings.

## 🛠 Tech Stack

- **Backend:** Python (Flask)
- **Database:** MongoDB (using PyMongo)
- **Frontend:** HTML5, CSS3, JavaScript (Jinja2 Templates)
- **Authentication:** Bcrypt (Password Hashing) & Flask-Session
- **Deployment:** Vercel (Serverless Functions)

---

## 🗄️ Database Schema (Collections)

1. **`users`**: Stores employee and admin credentials, roles, leave balances, and status.
2. **`leaves`**: Stores individual leave applications, dates, request types, and approval status.
3. **`notifications`**: Stores system and user-level notifications.
4. **`settings`**: Manages global application settings like policy defaults.

---

## 📦 Local Installation

Follow these steps to run the project on your local machine:

### 1. Prerequisites
- Python 3.13 or higher gracefully installed.
- MongoDB Server running locally or via MongoDB Atlas.

### 2. Setup Guide

```bash
# Clone the repository
git clone https://github.com/rabiasiddique-dev/Employee-Leave-Management.git
cd Employee-Leave-Management

# Create and activate a Virtual Environment
python -m venv venv

# For Windows:
venv\Scripts\activate

# Install all required Python packages
pip install -r requirements.txt
```

### 3. Environment Variables
Create a file named `.env` in the root directory and add your configurations:

```env
SECRET_KEY=your_secret_key_here
MONGO_URI=mongodb://localhost:27017/leaveflow_db
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
```

### 4. Run the Application
Start the Flask server from your terminal:

```bash
python app.py
```
*Visit `http://127.0.0.1:5000` in your web browser.*

---

## 🚀 Live Deployment on Vercel

This repository is pre-configured to be easily deployed on [Vercel](https://vercel.com/) via the existing `vercel.json` file.

1. Create a free account on **MongoDB Atlas** and grab your cloud database `MONGO_URI`.
2. Link your GitHub repository to a new project in your **Vercel Dashboard**.
3. Under **Environment Variables**, provide all the keys from your `.env` file *(especially the new MongoDB Atlas URI)*.
4. Click **Deploy**. Vercel will automatically detect the Python environment and build the application using serverless architecture.

---

## 🤝 Contribution Guidelines

We welcome contributions to make this Leave Management System even better! 
Feel free to open an **issue** or submit a **pull request** with detailed implementation notes.

---
*Created with ❤️ by Rabia Siddique*
