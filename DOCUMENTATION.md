# detailed Application Documentation

## Database Schema (MongoDB)

### Collections

1.  **users**
    -   `_id`: ObjectId
    -   `first_name`, `last_name`: String
    -   `email`: String (Unique)
    -   `password`: String (Hashed)
    -   `role`: String ('admin' or 'employee')
    -   `leave_balance`: Object (annual, sick, casual)
    -   `status`: String ('Active', 'Inactive')

2.  **leaves**
    -   `user_id`: ObjectId
    -   `leave_type`: String
    -   `start_date`, `end_date`: Date/String
    -   `status`: String ('Pending', 'Approved', 'Rejected')
    -   `reason`: String

3.  **notifications**
    -   Stores in-app notifications for users and admins.

4.  **settings**
    -   Stores global application settings like default leave policies.

## Project Structure

-   `app.py`: Main application entry point, contains routes and logic.
-   `templates/`: HTML templates for the frontend.
-   `static/`: CSS, JavaScript, and images.
-   `venv/`: Virtual environment (not included in repo).

## Authentication

Authentication is handled using Flask-Session. Passwords are hashed using `bcrypt` before storage.

-   **Login**: `/login`
-   **Register**: `/register`
-   **Logout**: `/logout`

## Key Routes

-   `/dashboard`: User/Admin dashboard.
-   `/apply-leave`: Leave application form.
-   `/admin/leaves`: Admin view of all leaves.
-   `/admin/employees`: Employee management.
