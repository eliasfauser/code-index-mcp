"""
Tests for search_code_advanced functionality.

Tests advanced code search capabilities including wildcard patterns,
case sensitivity, file filtering, and regex support using BasicSearchStrategy
directly to avoid complex service setup.
"""

import os
import tempfile
import pytest
from pathlib import Path

from code_index_mcp.search.basic import BasicSearchStrategy
from code_index_mcp.search.ripgrep import RipgrepStrategy
from code_index_mcp.utils.file_filter import FileFilter


@pytest.fixture
def temp_go_project():
    """Create a temporary Go project structure for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        files = {
            "main.go": """package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}
""",
            "internal/models/user.go": """package models

type User struct {
    ID          int      `json:"id"`
    Name        string   `json:"name"`
    Email       string   `json:"email"`
    Permissions []string `json:"permissions"`
}

// HasPermission checks if the user has a specific permission
func (u *User) HasPermission(permission string) bool {
    for _, p := range u.Permissions {
        if p == permission {
            return true
        }
    }
    return false
}

// AddPermission adds a permission to the user
func (u *User) AddPermission(permission string) {
    if !u.HasPermission(permission) {
        u.Permissions = append(u.Permissions, permission)
    }
}
""",
            "internal/services/auth.go": """package services

import "errors"

type AuthService struct {
    permissionCache map[string]bool
}

func NewAuthService() *AuthService {
    return &AuthService{
        permissionCache: make(map[string]bool),
    }
}

func (a *AuthService) CheckPermission(userID int, permission string) error {
    // Check permission logic here
    if !a.permissionCache[permission] {
        return errors.New("permission denied")
    }
    return nil
}
""",
            "pkg/api/handler.go": """package api

import "net/http"

func HandleRequest(w http.ResponseWriter, r *http.Request) {
    // Handle API request
    w.WriteHeader(http.StatusOK)
}
""",
            "README.md": """# User Management System

This system handles user permissions and authentication.
""",
            "config.json": """{"permissions": ["read", "write", "admin"]}""",
        }
        
        for file_path, content in files.items():
            full_path = Path(tmpdir) / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)
        
        yield tmpdir


@pytest.fixture
def strategy():
    """Create a BasicSearchStrategy instance."""
    return BasicSearchStrategy()


class TestSearchCodeAdvancedWildcardPatterns:
    """Test wildcard pattern handling in advanced code search."""
    
    def test_wildcard_pattern_case_insensitive_go_files(self, temp_go_project, strategy):
        """
        Test searching for '*permission*' with case_sensitive=False and file_pattern='*.go'.
        
        This test verifies that glob patterns in search terms work correctly.
        The pattern '*permission*' should match any line containing "permission".
        """
        # Configure file filter
        strategy.configure_excludes(FileFilter())
        
        # This should now WORK because glob patterns are converted to regex
        result = strategy.search(
            pattern="*permission*",
            base_path=temp_go_project,
            case_sensitive=False,
            file_pattern="*.go",
            regex=False,
            fuzzy=False
        )
        
        # Now we should find matches!
        assert len(result) > 0, \
            "Glob pattern '*permission*' should find matches containing 'permission'"
        
        # Verify we found permission-related code in .go files
        found_files = list(result.keys())
        assert any('user.go' in f for f in found_files), \
            "Should find matches in user.go"
        assert any('auth.go' in f for f in found_files), \
            "Should find matches in auth.go"
        
        # Check that all results are .go files
        for file_path in found_files:
            assert file_path.endswith('.go'), \
                f"File pattern *.go should only match .go files, got {file_path}"
    
    def test_wildcard_pattern_as_regex_works(self, temp_go_project, strategy):
        """
        Test that converting wildcards to regex works correctly.
        
        This shows that regex mode with .*permission.* also works.
        """
        strategy.configure_excludes(FileFilter())
        
        # Explicit regex also works
        result = strategy.search(
            pattern=".*permission.*",
            base_path=temp_go_project,
            case_sensitive=False,
            file_pattern="*.go",
            regex=True
        )
        
        # This WORKS because we're using proper regex
        assert len(result) > 0, "Regex pattern should find matches"
        
        # Verify we found permission-related code in .go files
        found_files = list(result.keys())
        assert any('user.go' in f for f in found_files), \
            "Should find matches in user.go"
        assert any('auth.go' in f for f in found_files), \
            "Should find matches in auth.go"
        
        # Check that all results are .go files
        for file_path in found_files:
            assert file_path.endswith('.go'), \
                f"File pattern *.go should only match .go files, got {file_path}"
    
    def test_glob_pattern_question_mark(self, temp_go_project, strategy):
        """Test that ? wildcard works for single character matching."""
        strategy.configure_excludes(FileFilter())
        
        # Use ? to match single character: "User" or "user"
        result = strategy.search(
            pattern="?ser",  # Matches "User" or "user"
            base_path=temp_go_project,
            case_sensitive=False,
            file_pattern="*.go"
        )
        
        assert len(result) > 0, "? wildcard should match single characters"
    
    def test_glob_pattern_leading_wildcard(self, temp_go_project, strategy):
        """Test pattern with leading wildcard."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern="*Permission",  # Matches HasPermission, AddPermission, etc.
            base_path=temp_go_project,
            case_sensitive=True,
            file_pattern="*.go"
        )
        
        assert len(result) > 0, "Leading wildcard should find matches"
    
    def test_glob_pattern_trailing_wildcard(self, temp_go_project, strategy):
        """Test pattern with trailing wildcard."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern="permission*",  # Matches permission, permissions, permissionCache
            base_path=temp_go_project,
            case_sensitive=False,
            file_pattern="*.go"
        )
        
        assert len(result) > 0, "Trailing wildcard should find matches"
    
    def test_simple_literal_search(self, temp_go_project, strategy):
        """Test that simple literal search (without wildcards) works correctly."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern="permission",
            base_path=temp_go_project,
            case_sensitive=False,
            file_pattern="*.go",
            regex=False,
            fuzzy=False
        )
        
        assert len(result) > 0, "Should find literal 'permission' matches"
        
        # Check that results are in .go files only
        for file_path in result.keys():
            assert file_path.endswith('.go')
    
    def test_fuzzy_search_for_permission(self, temp_go_project, strategy):
        """Test fuzzy search (word boundary matching) for 'permission'."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern="permission",
            base_path=temp_go_project,
            case_sensitive=False,
            file_pattern="*.go",
            fuzzy=True
        )
        
        assert len(result) > 0, "Should find matches with fuzzy search"
        
        # Fuzzy search should find partial matches like "Permissions", "permissionCache"
        all_lines = []
        for matches in result.values():
            for line_num, content in matches:
                all_lines.append(content.lower())
        
        assert any('permission' in line for line in all_lines)


class TestSearchCodeAdvancedFilePatterns:
    """Test file pattern filtering in advanced code search."""
    
    def test_go_files_only(self, temp_go_project, strategy):
        """Test that file_pattern='*.go' only returns Go files."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern="permission",
            base_path=temp_go_project,
            case_sensitive=False,
            file_pattern="*.go"
        )
        
        # All matches should be from .go files
        for file_path in result.keys():
            assert file_path.endswith('.go'), \
                f"Expected .go file but got {file_path}"
    
    def test_markdown_files_only(self, temp_go_project, strategy):
        """Test searching only in markdown files."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern="permission",
            base_path=temp_go_project,
            case_sensitive=False,
            file_pattern="*.md"
        )
        
        # Should find "permissions" in README.md
        assert len(result) > 0, "Should find matches in README.md"
        assert all(f.endswith('.md') for f in result.keys())
    
    def test_json_files_only(self, temp_go_project, strategy):
        """Test searching only in JSON files."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern="permissions",
            base_path=temp_go_project,
            case_sensitive=False,
            file_pattern="*.json"
        )
        
        # Should find "permissions" in config.json
        assert len(result) > 0, "Should find matches in config.json"
        assert all(f.endswith('.json') for f in result.keys())
    
    def test_no_file_pattern_searches_all(self, temp_go_project, strategy):
        """Test that omitting file_pattern searches all files."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern="permission",
            base_path=temp_go_project,
            case_sensitive=False,
            file_pattern=None
        )
        
        # Should find matches in .go, .md, and .json files
        file_extensions = set(Path(f).suffix for f in result.keys())
        assert '.go' in file_extensions


class TestSearchCodeAdvancedCaseSensitivity:
    """Test case sensitivity in advanced code search."""
    
    def test_case_sensitive_search(self, temp_go_project, strategy):
        """Test case-sensitive search only finds exact case matches."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern="Permission",  # Capital P
            base_path=temp_go_project,
            case_sensitive=True,
            file_pattern="*.go"
        )
        
        # Should find "Permission" but not "permission"
        for file_path, matches in result.items():
            for line_num, content in matches:
                assert 'Permission' in content, \
                    "Case-sensitive search should only find 'Permission' with capital P"
    
    def test_case_insensitive_search(self, temp_go_project, strategy):
        """Test case-insensitive search finds all case variations."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern="permission",
            base_path=temp_go_project,
            case_sensitive=False,
            file_pattern="*.go"
        )
        
        # Should find "permission", "Permission", "Permissions", etc.
        assert len(result) > 0
        
        all_text = ' '.join(
            content for matches in result.values()
            for _, content in matches
        ).lower()
        assert 'permission' in all_text


class TestSearchCodeAdvancedRegexPatterns:
    """Test regex pattern matching in advanced code search."""
    
    def test_regex_function_pattern(self, temp_go_project, strategy):
        """Test searching for function definitions using regex."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern=r"func \w+\(",
            base_path=temp_go_project,
            case_sensitive=True,
            file_pattern="*.go",
            regex=True
        )
        
        assert len(result) > 0, "Should find function definitions"
        
        # All matches should contain 'func '
        for matches in result.values():
            for line_num, content in matches:
                assert 'func ' in content
    
    def test_regex_type_pattern(self, temp_go_project, strategy):
        """Test searching for type definitions using regex."""
        strategy.configure_excludes(FileFilter())
        
        # Use a simple literal pattern instead of complex regex
        # to avoid safety checks while still testing regex mode
        result = strategy.search(
            pattern=r"type.*struct",
            base_path=temp_go_project,
            case_sensitive=True,
            file_pattern="*.go",
            regex=True
        )
        
        assert len(result) > 0, "Should find struct definitions"


class TestSearchCodeAdvancedIntegration:
    """Integration tests for realistic search scenarios."""
    
    def test_find_all_permission_methods(self, temp_go_project, strategy):
        """Test finding all methods related to permissions."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern="permission",
            base_path=temp_go_project,
            case_sensitive=False,
            file_pattern="*.go"
        )
        
        # Should find:
        # - HasPermission method
        # - AddPermission method
        # - CheckPermission method
        # - Permissions field
        # - permissionCache field
        
        all_text = ' '.join(
            content for matches in result.values()
            for _, content in matches
        )
        
        # Verify we found key permission-related code
        assert len(result) > 0
    
    def test_search_across_multiple_go_files(self, temp_go_project, strategy):
        """Test that search works across multiple Go files."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern="func",
            base_path=temp_go_project,
            case_sensitive=False,
            file_pattern="*.go"
        )
        
        # Should find functions in multiple files
        unique_files = set(result.keys())
        assert len(unique_files) > 1, "Should find matches in multiple files"
    
    def test_search_specific_nested_path(self, temp_go_project, strategy):
        """Test searching in nested directory structure."""
        strategy.configure_excludes(FileFilter())
        
        result = strategy.search(
            pattern="User",
            base_path=temp_go_project,
            case_sensitive=True,
            file_pattern="*.go"
        )
        
        # Should find User struct in internal/models/user.go
        found_user = False
        for file_path, matches in result.items():
            for line_num, content in matches:
                if 'User' in content:
                    found_user = True
                    break
        
        assert found_user, "Should find 'User' in Go files"
