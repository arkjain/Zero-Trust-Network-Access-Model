import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime, timezone
import uuid

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

async def init_sample_data():
    # MongoDB connection
    mongo_url = os.environ['MONGO_URL']
    client = AsyncIOMotorClient(mongo_url)
    db = client[os.environ['DB_NAME']]
    
    print("Initializing ZTNA sample data...")
    
    # Sample Applications
    sample_applications = [
        {
            "id": str(uuid.uuid4()),
            "name": "Gmail",
            "description": "Corporate email service",
            "url": "https://mail.google.com",
            "icon_url": "https://ssl.gstatic.com/ui/v1/icons/mail/rfr/gmail.ico",
            "category": "productivity",
            "is_active": True,
            "requires_mfa": False,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "id": str(uuid.uuid4()),
            "name": "GitHub",
            "description": "Source code management and collaboration",
            "url": "https://github.com",
            "icon_url": "https://github.githubassets.com/favicons/favicon.svg",
            "category": "development",
            "is_active": True,
            "requires_mfa": True,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Slack",
            "description": "Team communication platform",
            "url": "https://slack.com",
            "icon_url": "https://a.slack-edge.com/80588/marketing/img/icons/icon_slack_hash_colored.svg",
            "category": "communication",
            "is_active": True,
            "requires_mfa": False,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Jira",
            "description": "Project management and issue tracking",
            "url": "https://atlassian.com/software/jira",
            "icon_url": "https://wac-cdn.atlassian.com/assets/img/favicons/atlassian/favicon.png",
            "category": "project-management",
            "is_active": True,
            "requires_mfa": False,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "id": str(uuid.uuid4()),
            "name": "AWS Console",
            "description": "Amazon Web Services management console",
            "url": "https://aws.amazon.com/console/",
            "icon_url": "https://a0.awsstatic.com/libra-css/images/logos/aws_smile-header-desktop-en-white_59x35@2x.png",
            "category": "infrastructure",
            "is_active": True,
            "requires_mfa": True,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Salesforce",
            "description": "Customer relationship management platform",
            "url": "https://salesforce.com",
            "icon_url": "https://c1.sfdcstatic.com/etc/designs/sfdc-www/en_us/favicon.ico",
            "category": "crm",
            "is_active": True,
            "requires_mfa": False,
            "created_at": datetime.now(timezone.utc)
        }
    ]
    
    # Clear existing applications
    await db.applications.delete_many({})
    
    # Insert sample applications
    await db.applications.insert_many(sample_applications)
    print(f"✅ Created {len(sample_applications)} sample applications")
    
    # Sample Access Policies
    app_ids = [app["id"] for app in sample_applications]
    
    sample_policies = [
        {
            "id": str(uuid.uuid4()),
            "name": "Admin Full Access",
            "description": "Administrators have access to all applications at any time",
            "user_roles": ["admin"],
            "applications": app_ids,
            "time_restrictions": None,
            "location_restrictions": None,
            "is_active": True,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "id": str(uuid.uuid4()),
            "name": "User Business Hours",
            "description": "Regular users can access productivity and communication apps during business hours",
            "user_roles": ["user"],
            "applications": [app["id"] for app in sample_applications if app["category"] in ["productivity", "communication", "project-management"]],
            "time_restrictions": {
                "start": "09:00",
                "end": "18:00",
                "days": ["monday", "tuesday", "wednesday", "thursday", "friday"]
            },
            "location_restrictions": None,
            "is_active": True,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Developer Access",
            "description": "Developers can access development tools and some infrastructure services",
            "user_roles": ["user"],
            "applications": [app["id"] for app in sample_applications if app["category"] in ["development", "productivity", "communication"]],
            "time_restrictions": {
                "start": "08:00",
                "end": "20:00",
                "days": ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday"]
            },
            "location_restrictions": None,
            "is_active": True,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Guest Limited Access",
            "description": "Guests have limited access to basic communication tools",
            "user_roles": ["guest"],
            "applications": [app["id"] for app in sample_applications if app["category"] in ["communication"]],
            "time_restrictions": {
                "start": "10:00",
                "end": "16:00",
                "days": ["monday", "tuesday", "wednesday", "thursday", "friday"]
            },
            "location_restrictions": None,
            "is_active": True,
            "created_at": datetime.now(timezone.utc)
        }
    ]
    
    # Clear existing policies
    await db.access_policies.delete_many({})
    
    # Insert sample policies
    await db.access_policies.insert_many(sample_policies)
    print(f"✅ Created {len(sample_policies)} sample access policies")
    
    print("🎉 Sample data initialization completed!")
    print("\nSample Applications created:")
    for app in sample_applications:
        print(f"  - {app['name']} ({app['category']}): {app['url']}")
    
    print("\nSample Policies created:")
    for policy in sample_policies:
        print(f"  - {policy['name']}: {', '.join(policy['user_roles'])} roles")
    
    client.close()

if __name__ == "__main__":
    asyncio.run(init_sample_data())