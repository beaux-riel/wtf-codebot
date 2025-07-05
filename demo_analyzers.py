"""
Demo script to test the static analysis engines.
"""

import sys
from pathlib import Path

# Add the project root to sys.path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from wtf_codebot.analyzers import get_registry, analyze_file, PatternType, Severity
from wtf_codebot.discovery.models import FileNode, FileType


def create_sample_python_file() -> FileNode:
    """Create a sample Python file for testing."""
    python_code = '''
import os
import sys
import requests
from typing import List

# God class example
class UserManager:
    def __init__(self):
        self.users = []
        self.sessions = {}
        self.permissions = {}
        self.audit_log = []
        self.cache = {}
        self.config = {}
        self.database = None
        
    def create_user(self, name, email):
        """Create a new user."""
        user = {"name": name, "email": email}
        self.users.append(user)
        self.audit_log.append(f"User created: {name}")
        return user
    
    def delete_user(self, user_id):
        """Delete a user."""
        # This is a very long method that does too many things
        # and has deep nesting which is a code smell
        for i, user in enumerate(self.users):
            if user.get("id") == user_id:
                if user.get("active"):
                    if user.get("has_sessions"):
                        for session_id in self.sessions:
                            if self.sessions[session_id]["user_id"] == user_id:
                                if self.sessions[session_id]["active"]:
                                    if self.sessions[session_id]["type"] == "admin":
                                        # Very deep nesting - code smell
                                        self.sessions[session_id]["active"] = False
                                        self.audit_log.append(f"Admin session closed for user {user_id}")
                del self.users[i]
                break
        return True
    
    def authenticate_user(self, email, password):
        """Authenticate user."""
        # Magic numbers - code smell
        if len(password) < 8:
            return False
        if len(email) < 5:
            return False
        # More logic here...
        return True

# Potential singleton pattern
class DatabaseConnection:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

# Factory pattern
def create_user_manager(user_type):
    """Factory method for creating different user managers."""
    if user_type == "admin":
        return AdminUserManager()
    elif user_type == "regular":
        return RegularUserManager()
    elif user_type == "guest":
        return GuestUserManager()
    else:
        return None

# Unused variable example
def process_data():
    unused_var = "This variable is never used"
    data = [1, 2, 3, 4, 5]
    return sum(data)

# Duplicate code example
def calculate_total_price(items):
    total = 0
    for item in items:
        total += item.price
    return total

def calculate_total_cost(products):
    total = 0
    for product in products:
        total += product.price
    return total
'''
    
    file_node = FileNode(
        path=Path("sample_user_manager.py"),
        file_type=FileType.PYTHON,
        size=len(python_code),
        last_modified=0.0,
        content=python_code
    )
    
    # Simulate parser results
    file_node.functions = {
        "create_user", "delete_user", "authenticate_user", 
        "create_user_manager", "process_data", 
        "calculate_total_price", "calculate_total_cost"
    }
    file_node.classes = {"UserManager", "DatabaseConnection"}
    file_node.variables = {"unused_var", "data", "total"}
    file_node.imports = {"os", "sys", "requests", "typing"}
    
    return file_node


def create_sample_javascript_file() -> FileNode:
    """Create a sample JavaScript file for testing."""
    js_code = '''
const express = require('express');
const axios = require('axios');

// Callback hell example
function processUserData(userId, callback) {
    getUserById(userId, (err, user) => {
        if (err) {
            callback(err);
        } else {
            getProfileData(user.id, (err, profile) => {
                if (err) {
                    callback(err);
                } else {
                    getPreferences(user.id, (err, prefs) => {
                        if (err) {
                            callback(err);
                        } else {
                            // Very deep nesting - callback hell
                            callback(null, { user, profile, prefs });
                        }
                    });
                }
            });
        }
    });
}

// Large function example
function complexDataProcessor(data) {
    // This function is intentionally long to trigger the large function detection
    let result = {};
    
    // Line 1 of processing
    if (data.type === 'user') {
        result.processedType = 'USER_DATA';
    }
    
    // Lines 2-50 of processing (simulated)
    for (let i = 0; i < data.items.length; i++) {
        let item = data.items[i];
        if (item.category === 'A') {
            if (item.subcategory === 'A1') {
                if (item.priority === 'high') {
                    result[`item_${i}`] = processHighPriorityA1(item);
                } else if (item.priority === 'medium') {
                    result[`item_${i}`] = processMediumPriorityA1(item);
                } else {
                    result[`item_${i}`] = processLowPriorityA1(item);
                }
            }
        }
        // Many more lines of similar processing...
        // This would continue for 50+ lines to trigger the detection
    }
    
    return result;
}

// Promise hell example
function fetchUserDataWithPromises(userId) {
    return fetchUser(userId)
        .then(user => fetchProfile(user.id))
        .then(profile => fetchPreferences(profile.userId))
        .then(prefs => fetchSettings(prefs.userId))
        .then(settings => {
            // No .catch() - missing error handling
            return { profile, prefs, settings };
        });
}

// Magic numbers
function calculateDiscount(price, userType) {
    if (userType === 'premium') {
        return price * 0.85; // Magic number
    } else if (userType === 'gold') {
        return price * 0.90; // Magic number
    } else if (price > 100) {
        return price * 0.95; // Magic number
    }
    return price;
}

// Unused variables
function processOrder(order) {
    const unusedVariable = 'This is never used';
    const anotherUnused = calculateSomething();
    
    return order.total;
}

// Class with many methods (potential god class)
class OrderManager {
    constructor() {
        this.orders = [];
        this.customers = [];
        this.inventory = [];
        this.shipping = [];
        this.payments = [];
    }
    
    createOrder(orderData) { /* implementation */ }
    updateOrder(orderId, data) { /* implementation */ }
    deleteOrder(orderId) { /* implementation */ }
    processPayment(orderId) { /* implementation */ }
    updateInventory(items) { /* implementation */ }
    calculateShipping(address) { /* implementation */ }
    sendNotification(orderId) { /* implementation */ }
    generateInvoice(orderId) { /* implementation */ }
    trackShipment(shipmentId) { /* implementation */ }
    handleReturn(orderId) { /* implementation */ }
    // ... many more methods would be here
}
'''
    
    file_node = FileNode(
        path=Path("sample_order_manager.js"),
        file_type=FileType.JAVASCRIPT,
        size=len(js_code),
        last_modified=0.0,
        content=js_code
    )
    
    # Simulate parser results
    file_node.functions = {
        "processUserData", "complexDataProcessor", "fetchUserDataWithPromises",
        "calculateDiscount", "processOrder"
    }
    file_node.classes = {"OrderManager"}
    file_node.variables = {"express", "axios", "result", "unusedVariable"}
    file_node.imports = {"express", "axios"}
    
    return file_node


def print_analysis_results(file_path: str, result):
    """Print analysis results in a formatted way."""
    print(f"\n{'='*60}")
    print(f"Analysis Results for: {file_path}")
    print(f"{'='*60}")
    
    if not result:
        print("No analysis results available.")
        return
    
    # Print findings by type
    print(f"\n📊 FINDINGS SUMMARY:")
    print(f"Total findings: {len(result.findings)}")
    
    by_type = {}
    by_severity = {}
    
    for finding in result.findings:
        pattern_type = finding.pattern_type.value
        severity = finding.severity.value
        
        by_type[pattern_type] = by_type.get(pattern_type, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
    
    print("\nBy Type:")
    for pattern_type, count in by_type.items():
        print(f"  {pattern_type}: {count}")
    
    print("\nBy Severity:")
    for severity, count in by_severity.items():
        print(f"  {severity}: {count}")
    
    # Print detailed findings
    print(f"\n🔍 DETAILED FINDINGS:")
    for i, finding in enumerate(result.findings, 1):
        print(f"\n{i}. {finding.pattern_name} ({finding.pattern_type.value})")
        print(f"   Severity: {finding.severity.value}")
        print(f"   Line: {finding.line_number}")
        print(f"   Message: {finding.message}")
        if finding.suggestion:
            print(f"   Suggestion: {finding.suggestion}")
    
    # Print metrics
    print(f"\n📈 METRICS:")
    for metric in result.metrics:
        print(f"  {metric.name}: {metric.value} - {metric.description}")
    
    # Print metadata
    if result.metadata:
        print(f"\n📋 METADATA:")
        for key, value in result.metadata.items():
            if isinstance(value, list):
                print(f"  {key}: {len(value)} items")
                if value:  # Show first few items
                    preview = ", ".join(str(v) for v in value[:3])
                    if len(value) > 3:
                        preview += "..."
                    print(f"    ({preview})")
            else:
                print(f"  {key}: {value}")


def main():
    """Main demo function."""
    print("🔧 WTF CodeBot - Static Analysis Demo")
    print("=" * 50)
    
    # Get the analyzer registry
    registry = get_registry()
    
    print(f"\n📋 Registry Statistics:")
    stats = registry.get_registry_stats()
    print(f"  Total analyzers: {stats['total_analyzers']}")
    print(f"  Supported languages: {', '.join(stats['supported_languages'])}")
    print(f"  Supported extensions: {', '.join(stats['supported_extensions'])}")
    
    # Test Python analysis
    print(f"\n🐍 Testing Python Analysis")
    python_file = create_sample_python_file()
    python_result = analyze_file(python_file)
    print_analysis_results("sample_user_manager.py", python_result)
    
    # Test JavaScript analysis
    print(f"\n🟨 Testing JavaScript Analysis")
    js_file = create_sample_javascript_file()
    js_result = analyze_file(js_file)
    print_analysis_results("sample_order_manager.js", js_result)
    
    print(f"\n✅ Analysis complete!")


if __name__ == "__main__":
    main()
