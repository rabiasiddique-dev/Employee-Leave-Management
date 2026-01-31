# Employee Leave Management System

A web-based Employee Leave Management System built with Flask (Python) and MongoDB. This application streamlines the process of requesting, approving, and tracking employee leaves.

## Features

-   **Role-Based Access**:
    -   **Admin**: Manage employees, approve/reject leaves, view reports, and manage settings.
    -   **Employee**: Apply for leave, view leave history, and check leave balance.
-   **Leave Management**: Support for Annual, Sick, Casual, Unpaid, Maternity, and Paternity leaves.
-   **Dashboard**: Overview of upcoming leaves and holidays.
-   **Notifications**: Email and in-app notifications for leave status changes.
-   **Security**: Secure login with hashed passwords.

## Tech Stack

-   **Backend**: Python (Flask)
-   **Database**: MongoDB
-   **Frontend**: HTML, CSS, JavaScript (Jinja2 Templates)
-   **Authentication**: Session-based auth

## Prerequisites

-   Python 3.13 or higher
-   MongoDB (Locally installed or Atlas)

## Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/rabiasiddique-dev/Employee-Leave-Management.git
    cd Employee-Leave-Management
    ```

2.  **Create and activate a virtual environment**:
    ```bash
    # Windows
    python -m venv venv
    venv\Scripts\activate
    ```

3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configuration**:
    -   Create a `.env` file in the root directory.
    -   Add the following variables:
        ```env
        SECRET_KEY=your_secret_key
        MONGO_URI=mongodb://localhost:27017/leaveflow_db
        MAIL_SERVER=smtp.gmail.com
        MAIL_PORT=587
        MAIL_USE_TLS=true
        MAIL_USERNAME=your_email@gmail.com
        MAIL_PASSWORD=your_app_password
        ```

## Running the Application

1.  **Start the server**:
    ```bash
    python app.py
    ```

2.  **Access the app**:
    Open your browser and visit `http://127.0.0.1:5000`.

3.  **First Run**:
    -   The application will prompt you to create an Admin account via the CLI if none exists, or you can register through the UI if enabled.
