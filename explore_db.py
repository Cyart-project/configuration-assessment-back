import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from urllib.parse import quote_plus
from dotenv import load_dotenv
import os

# Load from .env
load_dotenv()

# MongoDB setup

username = quote_plus(os.getenv("MONGO_USERNAME"))
password = quote_plus(os.getenv("MONGO_PASSWORD"))
cluster = os.getenv("MONGO_CLUSTER")
print(f"Connecting to MongoDB cluster: {cluster} with user: {username}")
MONGO_URI = f"mongodb+srv://{username}:{password}@{cluster}/?retryWrites=true&w=majority&appName=WazuhLogsDB"


# Create the client
mongo_client = AsyncIOMotorClient(MONGO_URI)

# Databases to skip
SKIP_DATABASES = {"admin", "local", "sample_mflix"}

async def explore_database():
    with open('database_exploration1.txt', 'w', encoding='utf-8') as file:
        try:
            # List all databases
            database_names = await mongo_client.list_database_names()
            file.write(f"Databases found: {database_names}\n\n")

            # Filter out unwanted databases
            filtered_databases = [db for db in database_names if db not in SKIP_DATABASES]

            for db_name in filtered_databases:
                file.write(f"Exploring database: {db_name}\n")
                db = mongo_client[db_name]

                # List all collections in the database
                collection_names = await db.list_collection_names()
                file.write(f"Collections in {db_name}: {collection_names}\n")

                # Iterate through each collection
                for coll_name in collection_names:
                    file.write(f"\nFetching documents from collection: {coll_name}\n")
                    collection = db[coll_name]

                    # Fetch all documents in the collection
                    cursor = collection.find()
                    count = 0
                    async for doc in cursor:
                        file.write(f"\nDocument {count + 1}:\n")
                        file.write(f"{doc}\n")
                        file.write("-" * 50 + "\n")
                        count += 1

                    if count == 0:
                        file.write(f"No documents found in collection {coll_name}.\n")
                file.write("\n" + "="*60 + "\n\n")

        except Exception as e:
            file.write(f"\nError exploring database: {e}\n")
        finally:
            # Close the MongoDB connection
            mongo_client.close()
            file.write("MongoDB connection closed.\n")

# Run the async function
if __name__ == "__main__":
    asyncio.run(explore_database())
