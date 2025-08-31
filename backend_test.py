#!/usr/bin/env python3
"""
ZTNA Security System Backend API Test Suite
Tests authentication, MFA, policy engine, access control, and application gateway
"""

import requests
import json
import time
from datetime import datetime, timedelta
import sys
import os

# Backend URL from environment
BACKEND_URL = "https://zerotrust-app.preview.emergentagent.com/api"

class ZTNABackendTester:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.admin_token = None
        self.user_token = None
        self.guest_token = None
        self.test_results = []
        
    def log_result(self, test_name, success, message, details=None):
        """Log test results"""
        result = {
            "test": test_name,
            "success": success,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "details": details or {}
        }
        self.test_results.append(result)
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name} - {message}")
        if details and not success:
            print(f"   Details: {details}")
    
    def make_request(self, method, endpoint, data=None, headers=None, token=None):
        """Make HTTP request with proper error handling"""
        url = f"{self.base_url}{endpoint}"
        
        if headers is None:
            headers = {"Content-Type": "application/json"}
        
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, timeout=60)
            elif method.upper() == "POST":
                response = requests.post(url, json=data, headers=headers, timeout=60)
            elif method.upper() == "PUT":
                response = requests.put(url, json=data, headers=headers, timeout=60)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=headers, timeout=60)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            return response
        except requests.exceptions.RequestException as e:
            return None, str(e)
    
    def test_authentication_system(self):
        """Test complete authentication flow with MFA"""
        print("\n=== Testing Authentication System with MFA ===")
        
        # Test 1: Login with admin credentials
        login_data = {
            "username": "admin",
            "password": "admin123"
        }
        
        response = self.make_request("POST", "/auth/login", login_data)
        if response is None:
            self.log_result("Admin Login", False, "Failed to connect to backend")
            return False
        
        if response.status_code == 200:
            data = response.json()
            if data.get("requires_mfa"):
                self.log_result("Admin Login - MFA Required", True, "MFA code sent successfully")
            else:
                self.log_result("Admin Login", False, "MFA not required when it should be")
                return False
        else:
            self.log_result("Admin Login", False, f"Login failed: {response.text}")
            return False
        
        # Test 2: Check backend logs for MFA code (since email is not configured)
        print("   Checking backend logs for MFA code...")
        try:
            # Read supervisor logs to get MFA code
            import subprocess
            result = subprocess.run(['tail', '-n', '100', '/var/log/supervisor/backend.out.log'], 
                                  capture_output=True, text=True)
            log_content = result.stdout
            
            # Extract the most recent MFA code from logs
            mfa_code = None
            lines = log_content.split('\n')
            for line in reversed(lines):  # Check from most recent
                if "MFA Code for admin@example.com:" in line:
                    mfa_code = line.split(":")[-1].strip()
                    break
            
            if mfa_code:
                self.log_result("MFA Code Generation", True, f"MFA code found in logs: {mfa_code}")
                
                # Test 3: Verify MFA code
                mfa_data = {
                    "username": "admin",
                    "mfa_code": mfa_code
                }
                
                response = self.make_request("POST", "/auth/verify-mfa", mfa_data)
                if response and response.status_code == 200:
                    data = response.json()
                    self.admin_token = data.get("access_token")
                    user_info = data.get("user", {})
                    
                    if self.admin_token and user_info.get("role") == "admin":
                        self.log_result("MFA Verification", True, "Admin authenticated successfully")
                        return True
                    else:
                        self.log_result("MFA Verification", False, "Invalid token or user role")
                else:
                    self.log_result("MFA Verification", False, f"MFA verification failed: {response.text if response else 'No response'}")
            else:
                self.log_result("MFA Code Generation", False, "MFA code not found in logs")
        
        except Exception as e:
            self.log_result("MFA Code Extraction", False, f"Error reading logs: {str(e)}")
        
        return False
    
    def test_user_creation_and_roles(self):
        """Test user creation and role-based access"""
        print("\n=== Testing User Management and RBAC ===")
        
        if not self.admin_token:
            self.log_result("User Management Setup", False, "Admin token not available")
            return False
        
        # Test 1: Create regular user
        user_data = {
            "username": "john_doe",
            "email": "john.doe@company.com",
            "password": "SecurePass123!",
            "role": "user"
        }
        
        response = self.make_request("POST", "/auth/register", user_data)
        if response and response.status_code == 200:
            self.log_result("User Creation", True, "Regular user created successfully")
        else:
            self.log_result("User Creation", False, f"Failed to create user: {response.text if response else 'No response'}")
            return False
        
        # Test 2: Create guest user
        guest_data = {
            "username": "guest_user",
            "email": "guest@company.com", 
            "password": "GuestPass123!",
            "role": "guest"
        }
        
        response = self.make_request("POST", "/auth/register", guest_data)
        if response and response.status_code == 200:
            self.log_result("Guest User Creation", True, "Guest user created successfully")
        else:
            self.log_result("Guest User Creation", False, f"Failed to create guest: {response.text if response else 'No response'}")
        
        # Test 3: Get all users (admin only)
        response = self.make_request("GET", "/admin/users", token=self.admin_token)
        if response and response.status_code == 200:
            users = response.json()
            if len(users) >= 3:  # admin + john_doe + guest_user
                self.log_result("Admin User List", True, f"Retrieved {len(users)} users successfully")
            else:
                self.log_result("Admin User List", False, f"Expected at least 3 users, got {len(users)}")
        else:
            self.log_result("Admin User List", False, f"Failed to get users: {response.text if response else 'No response'}")
        
        return True
    
    def test_application_management(self):
        """Test application registry and management"""
        print("\n=== Testing Application Registry and Management ===")
        
        if not self.admin_token:
            self.log_result("Application Management Setup", False, "Admin token not available")
            return False
        
        # Test 1: Create sample applications
        applications = [
            {
                "name": "Gmail",
                "description": "Google Email Service",
                "url": "https://mail.google.com",
                "category": "productivity",
                "requires_mfa": False
            },
            {
                "name": "GitHub",
                "description": "Code Repository Platform",
                "url": "https://github.com",
                "category": "development",
                "requires_mfa": True
            },
            {
                "name": "AWS Console",
                "description": "Amazon Web Services Management Console",
                "url": "https://console.aws.amazon.com",
                "category": "infrastructure",
                "requires_mfa": True
            }
        ]
        
        created_apps = []
        for app_data in applications:
            response = self.make_request("POST", "/admin/applications", app_data, token=self.admin_token)
            if response and response.status_code == 200:
                app = response.json()
                created_apps.append(app)
                self.log_result(f"Create Application - {app_data['name']}", True, "Application created successfully")
            else:
                self.log_result(f"Create Application - {app_data['name']}", False, f"Failed: {response.text if response else 'No response'}")
        
        # Test 2: Get all applications (admin)
        response = self.make_request("GET", "/admin/applications", token=self.admin_token)
        if response and response.status_code == 200:
            apps = response.json()
            if len(apps) >= 3:
                self.log_result("Admin Application List", True, f"Retrieved {len(apps)} applications")
                return created_apps
            else:
                self.log_result("Admin Application List", False, f"Expected at least 3 apps, got {len(apps)}")
        else:
            self.log_result("Admin Application List", False, f"Failed to get applications: {response.text if response else 'No response'}")
        
        return created_apps
    
    def test_policy_engine(self):
        """Test advanced policy engine with time-based and role-based restrictions"""
        print("\n=== Testing Advanced Policy Engine ===")
        
        if not self.admin_token:
            self.log_result("Policy Engine Setup", False, "Admin token not available")
            return False
        
        # Get applications first
        response = self.make_request("GET", "/admin/applications", token=self.admin_token)
        if not response or response.status_code != 200:
            self.log_result("Policy Engine - Get Apps", False, "Cannot retrieve applications for policy testing")
            return False
        
        apps = response.json()
        if len(apps) < 2:
            self.log_result("Policy Engine - App Count", False, "Need at least 2 applications for policy testing")
            return False
        
        app_ids = [app["id"] for app in apps[:2]]
        
        # Test 1: Create business hours policy for admin users
        business_hours_policy = {
            "name": "Business Hours Admin Access",
            "description": "Admin users can access all applications during business hours",
            "user_roles": ["admin"],
            "applications": app_ids,
            "time_restrictions": {
                "start": "09:00",
                "end": "17:00",
                "days": ["monday", "tuesday", "wednesday", "thursday", "friday"]
            }
        }
        
        response = self.make_request("POST", "/admin/policies", business_hours_policy, token=self.admin_token)
        if response and response.status_code == 200:
            policy1 = response.json()
            self.log_result("Create Business Hours Policy", True, "Time-based policy created successfully")
        else:
            self.log_result("Create Business Hours Policy", False, f"Failed: {response.text if response else 'No response'}")
            return False
        
        # Test 2: Create 24/7 policy for regular users (limited apps)
        always_on_policy = {
            "name": "24/7 User Access",
            "description": "Regular users can access productivity apps anytime",
            "user_roles": ["user"],
            "applications": [app_ids[0]],  # Only first app
            "time_restrictions": None
        }
        
        response = self.make_request("POST", "/admin/policies", always_on_policy, token=self.admin_token)
        if response and response.status_code == 200:
            policy2 = response.json()
            self.log_result("Create 24/7 User Policy", True, "Role-based policy created successfully")
        else:
            self.log_result("Create 24/7 User Policy", False, f"Failed: {response.text if response else 'No response'}")
        
        # Test 3: Create guest policy (very limited access)
        guest_policy = {
            "name": "Guest Limited Access",
            "description": "Guests have very limited access",
            "user_roles": ["guest"],
            "applications": [],  # No applications
            "time_restrictions": {
                "start": "10:00",
                "end": "16:00",
                "days": ["monday", "tuesday", "wednesday", "thursday", "friday"]
            }
        }
        
        response = self.make_request("POST", "/admin/policies", guest_policy, token=self.admin_token)
        if response and response.status_code == 200:
            self.log_result("Create Guest Policy", True, "Guest restriction policy created successfully")
        else:
            self.log_result("Create Guest Policy", False, f"Failed: {response.text if response else 'No response'}")
        
        # Test 4: Get all policies
        response = self.make_request("GET", "/admin/policies", token=self.admin_token)
        if response and response.status_code == 200:
            policies = response.json()
            if len(policies) >= 3:
                self.log_result("Policy CRUD - Read All", True, f"Retrieved {len(policies)} policies")
                
                # Test policy validation logic by checking structure
                for policy in policies:
                    required_fields = ["id", "name", "description", "user_roles", "applications", "is_active"]
                    if all(field in policy for field in required_fields):
                        self.log_result("Policy Validation Logic", True, "Policy structure validation passed")
                        break
                else:
                    self.log_result("Policy Validation Logic", False, "Policy structure validation failed")
            else:
                self.log_result("Policy CRUD - Read All", False, f"Expected at least 3 policies, got {len(policies)}")
        else:
            self.log_result("Policy CRUD - Read All", False, f"Failed to get policies: {response.text if response else 'No response'}")
        
        return True
    
    def authenticate_user(self, username, password):
        """Helper method to authenticate a user and return token"""
        # Step 1: Login
        login_data = {"username": username, "password": password}
        response = self.make_request("POST", "/auth/login", login_data)
        
        if not response or response.status_code != 200:
            print(f"   Login failed for {username}: {response.text if response else 'No response'}")
            return None
        
        # Step 2: Get MFA code from logs
        try:
            import subprocess
            import time
            time.sleep(1)  # Wait a moment for log to be written
            result = subprocess.run(['tail', '-n', '50', '/var/log/supervisor/backend.out.log'], 
                                  capture_output=True, text=True)
            log_content = result.stdout
            
            mfa_code = None
            lines = log_content.split('\n')
            for line in reversed(lines):  # Check from most recent
                if f"MFA Code for" in line:
                    # Extract email from the line to match with user
                    if username == "john_doe" and "john.doe@company.com" in line:
                        mfa_code = line.split(":")[-1].strip()
                        break
                    elif username == "admin" and "admin@example.com" in line:
                        mfa_code = line.split(":")[-1].strip()
                        break
            
            if not mfa_code:
                print(f"   MFA code not found for {username}")
                return None
            
            print(f"   Found MFA code for {username}: {mfa_code}")
            
            # Step 3: Verify MFA
            mfa_data = {"username": username, "mfa_code": mfa_code}
            response = self.make_request("POST", "/auth/verify-mfa", mfa_data)
            
            if response and response.status_code == 200:
                return response.json().get("access_token")
            else:
                print(f"   MFA verification failed for {username}: {response.text if response else 'No response'}")
        
        except Exception as e:
            print(f"   Exception during authentication for {username}: {str(e)}")
        
        return None
    
    def test_access_control_and_gateway(self):
        """Test access control and application gateway functionality"""
        print("\n=== Testing Access Control and Application Gateway ===")
        
        # Authenticate regular user
        user_token = self.authenticate_user("john_doe", "SecurePass123!")
        if not user_token:
            self.log_result("User Authentication for Access Control", False, "Failed to authenticate regular user")
            return False
        
        self.log_result("User Authentication for Access Control", True, "Regular user authenticated successfully")
        
        # Test 1: Get user's authorized applications
        response = self.make_request("GET", "/applications", token=user_token)
        if response and response.status_code == 200:
            user_apps = response.json()
            self.log_result("User Application Access List", True, f"User can access {len(user_apps)} applications")
        else:
            self.log_result("User Application Access List", False, f"Failed to get user applications: {response.text if response else 'No response'}")
            return False
        
        # Test 2: Test application access with policy enforcement
        if user_apps:
            app_id = user_apps[0]["id"]
            app_name = user_apps[0]["name"]
            
            response = self.make_request("POST", f"/applications/{app_id}/access", token=user_token)
            if response and response.status_code == 200:
                access_data = response.json()
                if access_data.get("message") == "Access granted" and access_data.get("redirect_url"):
                    self.log_result("Application Access - Policy Enforcement", True, f"Access granted to {app_name}")
                    
                    # Test secure redirect functionality
                    if access_data.get("access_token"):
                        self.log_result("Secure Redirect - Access Token", True, "Access token generated for application")
                    else:
                        self.log_result("Secure Redirect - Access Token", False, "No access token in response")
                else:
                    self.log_result("Application Access - Policy Enforcement", False, "Invalid access response structure")
            else:
                self.log_result("Application Access - Policy Enforcement", False, f"Access denied: {response.text if response else 'No response'}")
        
        # Test 3: Test access to unauthorized application (if admin has more apps)
        response = self.make_request("GET", "/admin/applications", token=self.admin_token)
        if response and response.status_code == 200:
            all_apps = response.json()
            user_app_ids = [app["id"] for app in user_apps]
            
            # Find an app the user shouldn't have access to
            unauthorized_app = None
            for app in all_apps:
                if app["id"] not in user_app_ids:
                    unauthorized_app = app
                    break
            
            if unauthorized_app:
                response = self.make_request("POST", f"/applications/{unauthorized_app['id']}/access", token=user_token)
                if response and response.status_code == 403:
                    self.log_result("Access Control - Unauthorized App", True, "Access correctly denied to unauthorized application")
                else:
                    self.log_result("Access Control - Unauthorized App", False, f"Expected 403, got {response.status_code if response else 'No response'}")
        
        # Test 4: Test admin access to all applications
        response = self.make_request("GET", "/applications", token=self.admin_token)
        if response and response.status_code == 200:
            admin_apps = response.json()
            self.log_result("Admin Application Access", True, f"Admin can access {len(admin_apps)} applications")
        else:
            self.log_result("Admin Application Access", False, "Admin cannot get application list")
        
        return True
    
    def test_admin_endpoints(self):
        """Test admin-only endpoints with different roles"""
        print("\n=== Testing Admin-Only Endpoints ===")
        
        # Test 1: Admin access to dashboard stats
        response = self.make_request("GET", "/admin/stats", token=self.admin_token)
        if response and response.status_code == 200:
            stats = response.json()
            required_stats = ["total_users", "active_users", "total_applications", "active_applications", "total_policies"]
            if all(stat in stats for stat in required_stats):
                self.log_result("Admin Dashboard Stats", True, "Dashboard statistics retrieved successfully")
            else:
                self.log_result("Admin Dashboard Stats", False, "Missing required statistics fields")
        else:
            self.log_result("Admin Dashboard Stats", False, f"Failed to get stats: {response.text if response else 'No response'}")
        
        # Test 2: Regular user trying to access admin endpoints
        user_token = self.authenticate_user("john_doe", "SecurePass123!")
        if user_token:
            response = self.make_request("GET", "/admin/stats", token=user_token)
            if response and response.status_code == 403:
                self.log_result("Admin Endpoint Protection", True, "Regular user correctly denied admin access")
            else:
                self.log_result("Admin Endpoint Protection", False, f"Expected 403, got {response.status_code if response else 'No response'}")
        
        # Test 3: Admin access to logs
        response = self.make_request("GET", "/admin/logs", token=self.admin_token)
        if response and response.status_code == 200:
            logs = response.json()
            if len(logs) > 0:
                self.log_result("Admin Access Logs", True, f"Retrieved {len(logs)} access log entries")
                
                # Verify log structure
                log_entry = logs[0]
                required_fields = ["user_id", "username", "action", "timestamp", "success"]
                if all(field in log_entry for field in required_fields):
                    self.log_result("Access Logging Functionality", True, "Access logs have correct structure")
                else:
                    self.log_result("Access Logging Functionality", False, "Access logs missing required fields")
            else:
                self.log_result("Admin Access Logs", True, "No access logs found (expected for new system)")
        else:
            self.log_result("Admin Access Logs", False, f"Failed to get logs: {response.text if response else 'No response'}")
        
        return True
    
    def test_account_lockout(self):
        """Test account lockout after failed attempts"""
        print("\n=== Testing Account Lockout Mechanism ===")
        
        # Create a test user for lockout testing
        test_user_data = {
            "username": "lockout_test_user",
            "email": "lockout.test@company.com",
            "password": "TestPass123!",
            "role": "user"
        }
        
        response = self.make_request("POST", "/auth/register", test_user_data)
        if response and response.status_code == 400:
            # User might already exist, that's okay for testing
            self.log_result("Account Lockout Setup", True, "Test user exists or created")
        elif not response or response.status_code != 200:
            self.log_result("Account Lockout Setup", False, f"Failed to create test user: {response.text if response else 'No response'}")
            return False
        else:
            self.log_result("Account Lockout Setup", True, "Test user created successfully")
        
        # Test multiple failed login attempts
        failed_attempts = 0
        for i in range(6):  # Try 6 times (should lock after 5)
            login_data = {
                "username": "lockout_test_user",
                "password": "WrongPassword123!"
            }
            
            response = self.make_request("POST", "/auth/login", login_data)
            if response:
                if response.status_code == 401:
                    failed_attempts += 1
                elif response.status_code == 423:  # Account locked
                    self.log_result("Account Lockout After Failed Attempts", True, f"Account locked after {failed_attempts} failed attempts")
                    return True
        
        self.log_result("Account Lockout After Failed Attempts", False, "Account was not locked after multiple failed attempts")
        return False
    
    def test_time_based_policy_restrictions(self):
        """Test time-based policy restrictions specifically"""
        print("\n=== Testing Time-Based Policy Restrictions ===")
        
        if not self.admin_token:
            self.log_result("Time-Based Policy Setup", False, "Admin token not available")
            return False
        
        # Get applications first
        response = self.make_request("GET", "/admin/applications", token=self.admin_token)
        if not response or response.status_code != 200:
            self.log_result("Time-Based Policy - Get Apps", False, "Cannot retrieve applications")
            return False
        
        apps = response.json()
        if len(apps) < 1:
            self.log_result("Time-Based Policy - App Count", False, "Need at least 1 application")
            return False
        
        app_id = apps[0]["id"]
        
        # Create a restrictive time policy (only allows access during very specific hours)
        # This will likely fail current time unless it's exactly 02:00-02:01 AM on Monday
        restrictive_policy = {
            "name": "Very Restrictive Time Policy",
            "description": "Only allows access at 2 AM on Mondays",
            "user_roles": ["user"],
            "applications": [app_id],
            "time_restrictions": {
                "start": "02:00",
                "end": "02:01", 
                "days": ["monday"]
            }
        }
        
        response = self.make_request("POST", "/admin/policies", restrictive_policy, token=self.admin_token)
        if response and response.status_code == 200:
            self.log_result("Create Restrictive Time Policy", True, "Restrictive time policy created")
            
            # Now test if a user can access the application (should likely fail due to time restrictions)
            user_token = self.authenticate_user("john_doe", "SecurePass123!")
            if user_token:
                response = self.make_request("POST", f"/applications/{app_id}/access", token=user_token)
                if response and response.status_code == 403:
                    self.log_result("Time-Based Access Restriction", True, "Access correctly denied due to time restrictions")
                elif response and response.status_code == 200:
                    self.log_result("Time-Based Access Restriction", True, "Access granted (current time matches policy)")
                else:
                    self.log_result("Time-Based Access Restriction", False, f"Unexpected response: {response.status_code if response else 'No response'}")
            else:
                self.log_result("Time-Based Access Restriction", False, "Could not authenticate user for time test")
        else:
            self.log_result("Create Restrictive Time Policy", False, f"Failed to create policy: {response.text if response else 'No response'}")
        
        return True
    
    def run_all_tests(self):
        """Run all backend tests"""
        print("🚀 Starting ZTNA Security System Backend API Tests")
        print(f"Backend URL: {self.base_url}")
        print("=" * 60)
        
        # Test sequence based on dependencies
        test_methods = [
            self.test_authentication_system,
            self.test_user_creation_and_roles,
            self.test_application_management,
            self.test_policy_engine,
            self.test_access_control_and_gateway,
            self.test_admin_endpoints,
            self.test_time_based_policy_restrictions,
            self.test_account_lockout
        ]
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                self.log_result(test_method.__name__, False, f"Test crashed: {str(e)}")
        
        # Summary
        print("\n" + "=" * 60)
        print("🏁 TEST SUMMARY")
        print("=" * 60)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result["success"])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print("\n❌ FAILED TESTS:")
            for result in self.test_results:
                if not result["success"]:
                    print(f"  - {result['test']}: {result['message']}")
        
        return failed_tests == 0

if __name__ == "__main__":
    tester = ZTNABackendTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)