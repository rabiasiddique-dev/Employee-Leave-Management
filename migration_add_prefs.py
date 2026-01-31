# migration_add_prefs.py
import os
from pymongo import MongoClient
from dotenv import load_dotenv
from bson import ObjectId # Agar _id ko ObjectId ke taur par handle karna hai (waise find se mil jayega)

# Load environment variables (assuming .env is in the same directory or parent)
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
else:
    # Fallback if .env is in parent (useful if script is in a 'scripts' subfolder)
    load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))


MONGO_URI = os.getenv('MONGO_URI')
# Extract DB name from URI robustly
if MONGO_URI:
    try:
        # Attempt to get DB name, handling potential errors if URI is malformed
        db_name_part = MONGO_URI.split('/')[-1]
        DB_NAME = db_name_part.split('?')[0] if '?' in db_name_part else db_name_part
    except IndexError:
        print("Error: MONGO_URI seems malformed. Could not extract database name.")
        DB_NAME = None # Or a default/fallback name if you have one
else:
    DB_NAME = None


if not MONGO_URI or not DB_NAME:
    print("Error: MONGO_URI not found or database name could not be determined from it in .env file.")
    exit()

try:
    client = MongoClient(MONGO_URI)
    # Ping the server to ensure connection before proceeding
    client.admin.command('ping')
    print(f"Successfully connected to MongoDB server. Using database: {DB_NAME}")
except Exception as e:
    print(f"MongoDB connection failed: {e}")
    print("Please ensure MongoDB is running and MONGO_URI in .env is correct.")
    exit()

db = client[DB_NAME]
users_collection = db.users

def add_default_notification_prefs():
    print(f"\n--- Adding default notification preferences to users in '{DB_NAME}.users' ---")
    # Find users who do not have the notification_preferences field
    # or where notification_preferences is null (though $exists:false should cover it)
    query = {'notification_preferences': {'$exists': False}}
    
    users_to_update_cursor = users_collection.find(query)
    # Convert cursor to list to avoid "Cursor exhausted" if you iterate multiple times or need count first
    users_to_update_list = list(users_to_update_cursor)
    
    if not users_to_update_list:
        print("No users found requiring update for notification preferences.")
        return

    print(f"Found {len(users_to_update_list)} user(s) to update.")
    updated_count = 0
    
    for user_doc in users_to_update_list:
        default_prefs = {
            'email_on_leave_applied': True,
            'email_on_leave_status_change': True
        }
        try:
            result = users_collection.update_one(
                {'_id': user_doc['_id']}, # Use the _id from the fetched document
                {'$set': {'notification_preferences': default_prefs}}
            )
            if result.modified_count > 0:
                updated_count += 1
                print(f"  Updated user: {user_doc.get('email', user_doc['_id'])}")
            # else:
            #     print(f"  User {user_doc.get('email', user_doc['_id'])} already had prefs or no change needed (unexpected).")

        except Exception as e:
            print(f"  Error updating user {user_doc.get('email', user_doc['_id'])}: {e}")
    
    print(f"\nFinished. Successfully updated {updated_count} user(s) with default notification preferences.")

if __name__ == '__main__':
    add_default_notification_prefs()
    client.close()
    print("MongoDB connection closed.")