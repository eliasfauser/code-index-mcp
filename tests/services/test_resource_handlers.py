"""
Tests for MCP resource handlers (files:// and config://).

These tests verify that resources work correctly with different path formats:
- Relative paths with and without leading slashes
- Paths with different separators
- Edge cases and security validations
"""
import os
import tempfile
import pytest
from pathlib import Path
from types import SimpleNamespace

from code_index_mcp.services.file_service import FileService
from code_index_mcp.services.project_management_service import ProjectManagementService


def _create_test_context(base_path: str, settings=None):
    """Create a mock MCP context for testing."""
    if settings is None:
        from code_index_mcp.project_settings import ProjectSettings
        settings = ProjectSettings(base_path, skip_load=True)
    
    ctx = SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=SimpleNamespace(
                base_path=base_path,
                settings=settings,
                file_count=0,
                index_manager=None
            )
        )
    )
    return ctx


class TestFileResourcePathFormats:
    """Test files://{file_path} resource with various path formats."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Create a temporary directory structure
        self.temp_dir = tempfile.mkdtemp()
        self.test_files = {}
        
        # Create test files in various locations
        # Root level file
        self._create_test_file("README.md", "# Project README\nThis is the main readme.")
        
        # Nested file
        self._create_test_file("src/main.py", "def main():\n    print('Hello')\n")
        
        # Deeply nested file
        self._create_test_file("src/utils/helper.py", "# Helper functions\ndef helper():\n    pass\n")
        
        # File with special characters in name
        self._create_test_file("docs/file-with-dashes.txt", "Content with dashes")
        
        # File with spaces (if supported)
        self._create_test_file("docs/file with spaces.txt", "Content with spaces")
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def _create_test_file(self, rel_path: str, content: str):
        """Create a test file with given content."""
        full_path = os.path.join(self.temp_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)
        self.test_files[rel_path] = content
    
    def _get_service(self):
        """Get FileService instance with test context."""
        ctx = _create_test_context(self.temp_dir)
        return FileService(ctx)
    
    def test_simple_relative_path(self):
        """Test reading file with simple relative path."""
        service = self._get_service()
        content = service.get_file_content("README.md")
        assert content == self.test_files["README.md"]
    
    def test_relative_path_with_leading_slash(self):
        """Test that leading slash in relative path is handled correctly."""
        service = self._get_service()
        # Leading slash should be stripped and treated as relative path
        # This tests the common mistake users make
        try:
            content = service.get_file_content("/README.md")
            # If it works, verify it's the right content
            assert content == self.test_files["README.md"]
        except ValueError as e:
            # If it fails, ensure it's because of absolute path detection
            assert "Absolute file paths" in str(e) or "not allowed" in str(e)
    
    def test_nested_relative_path(self):
        """Test reading nested file with relative path."""
        service = self._get_service()
        content = service.get_file_content("src/main.py")
        assert content == self.test_files["src/main.py"]
    
    def test_nested_path_with_forward_slash(self):
        """Test nested path with forward slashes (Unix-style)."""
        service = self._get_service()
        content = service.get_file_content("src/utils/helper.py")
        assert content == self.test_files["src/utils/helper.py"]
    
    def test_nested_path_with_backslash(self):
        """Test nested path with backslashes (Windows-style)."""
        service = self._get_service()
        # Test with backslashes - should be normalized
        content = service.get_file_content("src\\utils\\helper.py")
        assert content == self.test_files["src/utils/helper.py"]
    
    def test_mixed_path_separators(self):
        """Test path with mixed separators."""
        service = self._get_service()
        content = service.get_file_content("src/utils\\helper.py")
        assert content == self.test_files["src/utils/helper.py"]
    
    def test_path_with_dot_notation(self):
        """Test path with ./ prefix."""
        service = self._get_service()
        content = service.get_file_content("./README.md")
        assert content == self.test_files["README.md"]
    
    def test_path_with_extra_slashes(self):
        """Test path with extra slashes."""
        service = self._get_service()
        # Extra slashes should be normalized
        content = service.get_file_content("src//utils//helper.py")
        assert content == self.test_files["src/utils/helper.py"]
    
    def test_file_with_dashes_in_name(self):
        """Test file with dashes in filename."""
        service = self._get_service()
        content = service.get_file_content("docs/file-with-dashes.txt")
        assert content == self.test_files["docs/file-with-dashes.txt"]
    
    def test_file_with_spaces_in_name(self):
        """Test file with spaces in filename."""
        service = self._get_service()
        content = service.get_file_content("docs/file with spaces.txt")
        assert content == self.test_files["docs/file with spaces.txt"]
    
    def test_nonexistent_file(self):
        """Test error handling for nonexistent file."""
        service = self._get_service()
        with pytest.raises(FileNotFoundError):
            service.get_file_content("nonexistent.py")
    
    def test_directory_traversal_attack_parent(self):
        """Test security: prevent directory traversal with ../ """
        service = self._get_service()
        with pytest.raises(ValueError) as exc_info:
            service.get_file_content("../../../etc/passwd")
        assert "traversal" in str(exc_info.value).lower() or "not allowed" in str(exc_info.value).lower()
    
    def test_directory_traversal_attack_mixed(self):
        """Test security: prevent directory traversal in middle of path."""
        service = self._get_service()
        with pytest.raises(ValueError) as exc_info:
            service.get_file_content("src/../../../etc/passwd")
        assert "traversal" in str(exc_info.value).lower() or "not allowed" in str(exc_info.value).lower()
    
    def test_absolute_path_unix(self):
        """Test that absolute Unix paths are handled (leading slash stripped)."""
        service = self._get_service()
        # Leading slash is stripped, so /etc/passwd becomes etc/passwd
        # which will fail because the file doesn't exist, not because it's absolute
        with pytest.raises(FileNotFoundError):
            service.get_file_content("/etc/passwd")
    
    def test_absolute_path_windows(self):
        """Test that absolute Windows paths are rejected."""
        service = self._get_service()
        with pytest.raises(ValueError) as exc_info:
            service.get_file_content("C:\\Windows\\System32\\config\\sam")
        assert "Absolute file paths" in str(exc_info.value) or "not allowed" in str(exc_info.value)
    
    def test_empty_path(self):
        """Test that empty path is rejected."""
        service = self._get_service()
        with pytest.raises(ValueError) as exc_info:
            service.get_file_content("")
        assert "empty" in str(exc_info.value).lower() or "cannot be empty" in str(exc_info.value).lower()
    
    def test_no_project_setup(self):
        """Test error when project is not set up."""
        ctx = SimpleNamespace(
            request_context=SimpleNamespace(
                lifespan_context=SimpleNamespace(
                    base_path=None,
                    settings=None,
                    file_count=0,
                    index_manager=None
                )
            )
        )
        service = FileService(ctx)
        with pytest.raises(ValueError) as exc_info:
            service.get_file_content("README.md")
        assert "project" in str(exc_info.value).lower() or "not set" in str(exc_info.value).lower()

class TestPathNormalization:
    """Test path normalization edge cases."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        # Create a simple test file
        test_file = os.path.join(self.temp_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("test content")
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_path_with_current_dir_references(self):
        """Test path with multiple ./ references."""
        ctx = _create_test_context(self.temp_dir)
        service = FileService(ctx)
        
        content = service.get_file_content("././test.txt")
        assert content == "test content"
    
    def test_unicode_in_path(self):
        """Test paths with unicode characters."""
        # Create a file with unicode name
        unicode_file = os.path.join(self.temp_dir, "файл.txt")
        try:
            with open(unicode_file, 'w', encoding='utf-8') as f:
                f.write("unicode content")
            
            ctx = _create_test_context(self.temp_dir)
            service = FileService(ctx)
            
            content = service.get_file_content("файл.txt")
            assert content == "unicode content"
        except (OSError, UnicodeError):
            # Some systems might not support unicode filenames
            pytest.skip("System doesn't support unicode filenames")


class TestResourceIntegration:
    """Integration tests for resource handlers."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a realistic project structure
        files = {
            "README.md": "# Test Project\n",
            "src/main.py": "def main():\n    pass\n",
            "src/__init__.py": "",
            "tests/test_main.py": "def test_main():\n    assert True\n",
            ".gitignore": "*.pyc\n__pycache__/\n",
        }
        
        for rel_path, content in files.items():
            full_path = os.path.join(self.temp_dir, rel_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_read_multiple_files_different_formats(self):
        """Test reading multiple files with different path formats."""
        service = FileService(_create_test_context(self.temp_dir))
        
        # Different ways to reference the same logical files
        test_cases = [
            ("README.md", "# Test Project\n"),
            ("src/main.py", "def main():\n    pass\n"),
            ("src/__init__.py", ""),
            ("tests/test_main.py", "def test_main():\n    assert True\n"),
        ]
        
        for path, expected_content in test_cases:
            content = service.get_file_content(path)
            assert content == expected_content, f"Failed for path: {path}"
    
    def test_read_hidden_files(self):
        """Test reading hidden files (starting with dot)."""
        service = FileService(_create_test_context(self.temp_dir))
        
        content = service.get_file_content(".gitignore")
        assert "*.pyc" in content


class TestResourceListing:
    """Test MCP resource listing functionality."""
    
    def test_list_resources_returns_config_resource(self):
        """Test that list_resources returns the config resource."""
        import asyncio
        from code_index_mcp.server import mcp
        
        # Get list of resources
        resources = asyncio.run(mcp.list_resources())
        
        # Should have at least the config resource
        assert len(resources) > 0
        
        # Find config resource (uri is a pydantic AnyUrl object)
        config_resources = [r for r in resources if str(r.uri) == "config://code-indexer"]
        assert len(config_resources) == 1
        
        config_resource = config_resources[0]
        assert str(config_resource.uri) == "config://code-indexer"
        assert config_resource.name is not None or config_resource.uri is not None
    
    def test_list_resource_templates_returns_files_template(self):
        """Test that list_resource_templates returns the files template."""
        import asyncio
        from code_index_mcp.server import mcp
        
        # Get list of resource templates
        templates = asyncio.run(mcp.list_resource_templates())
        
        # Should have the files template
        assert len(templates) > 0
        
        # Find files template
        files_templates = [t for t in templates if "files://" in t.uriTemplate]
        assert len(files_templates) == 1
        
        files_template = files_templates[0]
        assert files_template.uriTemplate == "files://{file_path}"
        assert files_template.name is not None or files_template.uriTemplate is not None
    
    def test_resources_are_discoverable(self):
        """Test that both static and template resources are discoverable."""
        import asyncio
        from code_index_mcp.server import mcp
        
        # Get both lists
        resources = asyncio.run(mcp.list_resources())
        templates = asyncio.run(mcp.list_resource_templates())
        
        # Should have at least one of each
        assert len(resources) >= 1, "Should have at least the config resource"
        assert len(templates) >= 1, "Should have at least the files template"
        
        # Collect all URIs/templates (convert AnyUrl to string)
        resource_uris = {str(r.uri) for r in resources}
        template_uris = {t.uriTemplate for t in templates}
        
        # Verify expected resources
        assert "config://code-indexer" in resource_uris
        assert "files://{file_path}" in template_uris
    
    def test_config_resource_has_metadata(self):
        """Test that config resource has proper metadata."""
        import asyncio
        from code_index_mcp.server import mcp
        
        resources = asyncio.run(mcp.list_resources())
        config_resources = [r for r in resources if str(r.uri) == "config://code-indexer"]
        
        assert len(config_resources) == 1
        config_resource = config_resources[0]
        
        # Check that it has some identifying information
        assert str(config_resource.uri) == "config://code-indexer"
        # At minimum, should have uri
        assert hasattr(config_resource, 'uri')
    
    def test_files_template_has_metadata(self):
        """Test that files template resource has proper metadata."""
        import asyncio
        from code_index_mcp.server import mcp
        
        templates = asyncio.run(mcp.list_resource_templates())
        files_templates = [t for t in templates if "files://" in t.uriTemplate]
        
        assert len(files_templates) == 1
        files_template = files_templates[0]
        
        # Check that it has proper template structure
        assert files_template.uriTemplate == "files://{file_path}"
        assert hasattr(files_template, 'uriTemplate')
        
        # Check if it has description or name (optional but good practice)
        # Note: These might be None if not set in the decorator
        assert files_template.uriTemplate is not None
    
    def test_read_resource_via_mcp_with_workspace_files(self):
        """Test reading actual files from the workspace through MCP resources."""
        import tempfile
        import os
        from types import SimpleNamespace
        from code_index_mcp.services.file_service import FileService
        from code_index_mcp.project_settings import ProjectSettings
        
        # Create a temporary workspace with test files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            readme_path = os.path.join(temp_dir, "README.md")
            readme_content = "# Test Project\nThis is a test readme for MCP resources."
            with open(readme_path, 'w') as f:
                f.write(readme_content)
            
            src_dir = os.path.join(temp_dir, "src")
            os.makedirs(src_dir)
            main_path = os.path.join(src_dir, "main.py")
            main_content = "def main():\n    print('Hello from MCP!')\n"
            with open(main_path, 'w') as f:
                f.write(main_content)
            
            nested_dir = os.path.join(src_dir, "utils")
            os.makedirs(nested_dir)
            helper_path = os.path.join(nested_dir, "helper.py")
            helper_content = "# Helper utilities\ndef helper():\n    return 'help'\n"
            with open(helper_path, 'w') as f:
                f.write(helper_content)
            
            # Create context with the temp directory
            settings = ProjectSettings(temp_dir, skip_load=True)
            ctx = SimpleNamespace(
                request_context=SimpleNamespace(
                    lifespan_context=SimpleNamespace(
                        base_path=temp_dir,
                        settings=settings,
                        file_count=0,
                        index_manager=None
                    )
                )
            )
            
            # Create FileService with this context
            service = FileService(ctx)
            
            # Test reading README.md
            content = service.get_file_content("README.md")
            assert content == readme_content
            
            # Test reading nested file
            content = service.get_file_content("src/main.py")
            assert content == main_content
            
            # Test reading deeply nested file
            content = service.get_file_content("src/utils/helper.py")
            assert content == helper_content
            
            # Test with different path formats
            content = service.get_file_content("./README.md")
            assert content == readme_content
            
            # Test with leading slash (should be stripped)
            content = service.get_file_content("/README.md")
            assert content == readme_content
            
            # Test with backslashes (Windows-style)
            content = service.get_file_content("src\\main.py")
            assert content == main_content
            
            # Test with mixed separators
            content = service.get_file_content("src/utils\\helper.py")
            assert content == helper_content
    
    def test_config_resource_readable(self):
        """Test that config resource can be listed and has correct URI format."""
        import asyncio
        from code_index_mcp.server import mcp
        
        resources = asyncio.run(mcp.list_resources())
        config_resources = [r for r in resources if str(r.uri) == "config://code-indexer"]
        
        assert len(config_resources) == 1
        
        # Verify URI scheme is correct
        uri_str = str(config_resources[0].uri)
        assert uri_str.startswith("config://")
        assert "code-indexer" in uri_str
