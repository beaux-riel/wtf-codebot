"""
FastAPI backend server for the wtf-codebot web UI.

This module provides a web interface for browsing the codebase structure,
managing file/directory exclusions, and running code analysis.
"""

import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any

import aiofiles
from fastapi import FastAPI, HTTPException, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from wtf_codebot.core.analysis_engine import AnalysisEngine
from wtf_codebot.core.config import Config


# Pydantic models for request/response
class FileTreeNode(BaseModel):
    name: str
    path: str
    is_file: bool
    is_excluded: bool
    children: Optional[List['FileTreeNode']] = None
    size: Optional[int] = None


class AnalysisRequest(BaseModel):
    directory: str
    excluded_paths: List[str] = []
    included_paths: List[str] = []  # Paths that should be included in analysis
    include_patterns: List[str] = []
    exclude_patterns: List[str] = []


class AnalysisResult(BaseModel):
    success: bool
    message: str
    analysis_data: Optional[Dict[str, Any]] = None
    file_path: Optional[str] = None


# Initialize FastAPI app
app = FastAPI(
    title="WTF Codebot Web UI",
    description="Web interface for analyzing codebases",
    version="1.0.0"
)

# Mount static files and templates
STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"

# Create directories if they don't exist
STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Global state for current analysis
current_analysis_state = {
    "directory": None,
    "excluded_paths": [],
    "included_paths": [],
    "analysis_result": None,
    "config": None
}

# Progress tracking state
progress_state = {
    "status": "ready",
    "message": "Ready to analyze",
    "progress": 0,
    "current_file": "",
    "current_language": "",
    "files_processed": 0,
    "total_files": 0
}

# Store for analysis history
from datetime import datetime
analysis_history = []  # List of completed analyses with timestamps


def progress_callback(language: str, file_path: str, current_index: int, total_count: int):
    """Progress callback function for analysis tracking."""
    global progress_state
    
    # Handle dependency analysis progress
    if language == "dependency":
        progress_state.update({
            "status": "analyzing",
            "message": file_path,  # file_path contains the progress message for dependency analysis
            "progress": int((current_index / total_count) * 100) if total_count > 0 else 0,
            "current_file": "",
            "current_language": "dependency",
            "files_processed": current_index,
            "total_files": total_count,
            "dependency_progress": {
                "message": file_path,
                "current": current_index,
                "total": total_count
            }
        })
    else:
        # Regular file analysis progress
        progress_state.update({
            "status": "analyzing",
            "message": f"Analyzing {language} files...",
            "progress": int((current_index / total_count) * 100) if total_count > 0 else 0,
            "current_file": file_path,
            "current_language": language,
            "files_processed": current_index,
            "total_files": total_count
        })


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the main web interface."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/progress")
async def get_progress():
    """Get current analysis progress."""
    return progress_state


@app.get("/api/file-tree")
async def get_file_tree_api(directory: str = "."):
    """Get the file tree structure for a directory."""
    try:
        directory_path = Path(directory).resolve()
        if not directory_path.exists():
            raise HTTPException(status_code=404, detail="Directory not found")
        
        if not directory_path.is_dir():
            raise HTTPException(status_code=400, detail="Path is not a directory")
        
        tree = build_file_tree(directory_path)
        
        # Add navigation info
        parent_path = str(directory_path.parent) if directory_path.parent != directory_path else None
        
        return JSONResponse(content={
            "tree": tree,
            "current_directory": str(directory_path),
            "parent_directory": parent_path,
            "directory_name": directory_path.name or str(directory_path)
        })
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/browse-directories")
async def browse_directories_api(path: str = "/"):
    """Browse directories for directory selection."""
    try:
        directory_path = Path(path).resolve()
        if not directory_path.exists():
            raise HTTPException(status_code=404, detail="Directory not found")
        
        if not directory_path.is_dir():
            raise HTTPException(status_code=400, detail="Path is not a directory")
        
        # Get directories only (no files)
        directories = []
        try:
            for item in sorted(directory_path.iterdir()):
                if item.is_dir() and not item.name.startswith('.'):
                    directories.append({
                        "name": item.name,
                        "path": str(item),
                        "is_accessible": True
                    })
        except PermissionError:
            # Skip directories we can't access
            pass
        
        # Add navigation info
        parent_path = str(directory_path.parent) if directory_path.parent != directory_path else None
        
        # Add common system directories for easy access
        common_dirs = []
        if str(directory_path) == str(Path.home()):
            common_dirs = [
                {"name": "Desktop", "path": str(Path.home() / "Desktop"), "is_common": True},
                {"name": "Documents", "path": str(Path.home() / "Documents"), "is_common": True},
                {"name": "Downloads", "path": str(Path.home() / "Downloads"), "is_common": True},
                {"name": "Projects", "path": str(Path.home() / "Projects"), "is_common": True},
                {"name": "Developer", "path": str(Path.home() / "Developer"), "is_common": True},
            ]
            # Filter to only existing directories
            common_dirs = [d for d in common_dirs if Path(d["path"]).exists()]
        
        return JSONResponse(content={
            "directories": directories,
            "common_directories": common_dirs,
            "current_directory": str(directory_path),
            "parent_directory": parent_path,
            "directory_name": directory_path.name or str(directory_path)
        })
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze")
async def analyze_codebase(request: AnalysisRequest):
    """Run code analysis on the specified directory."""
    try:
        directory_path = Path(request.directory).resolve()
        if not directory_path.exists():
            raise HTTPException(status_code=404, detail="Directory not found")
        
        # Update global state
        current_analysis_state["directory"] = str(directory_path)
        current_analysis_state["excluded_paths"] = request.excluded_paths
        current_analysis_state["included_paths"] = request.included_paths
        
        # Create config with exclusions  
        from wtf_codebot.core.config import get_config
        config = get_config()
        
        # Override with request parameters
        if request.excluded_paths:
            config.analysis.exclude_patterns.extend(request.excluded_paths)
        
        current_analysis_state["config"] = config
        
        # Reset progress state
        progress_state.update({
            "status": "analyzing",
            "message": "Starting analysis...",
            "progress": 0,
            "current_file": "",
            "current_language": "",
            "files_processed": 0,
            "total_files": 0
        })
        
        # If specific paths are included, analyze only those
        if request.included_paths:
            # Analyze only the included paths
            analyzer = AnalysisEngine(config)
            analysis_result = analyzer.analyze_selected_paths(directory_path, request.included_paths, progress_callback)
        else:
            # Run full analysis
            analyzer = AnalysisEngine(config)
            analysis_result = analyzer.analyze(directory_path, progress_callback)
        
        # Update progress to complete
        progress_state.update({
            "status": "complete",
            "message": "Analysis completed successfully",
            "progress": 100,
            "current_file": "",
            "current_language": "",
            "files_processed": progress_state.get("total_files", 0),
            "total_files": progress_state.get("total_files", 0)
        })
        
        # Store result
        current_analysis_state["analysis_result"] = analysis_result
        
        # Format the analysis result for display
        formatted_result = {
            "summary": analysis_result.get("summary", {}),
            "total_files": analysis_result.get("total_files", 0),
            "findings": analysis_result.get("findings", []),
            "metrics": analysis_result.get("metrics", {}),
            "dependencies": analysis_result.get("dependencies", []),
            "vulnerabilities": analysis_result.get("vulnerabilities", []),
        }
        
        # Store in history
        history_entry = {
            "id": len(analysis_history) + 1,
            "timestamp": datetime.now().isoformat(),
            "directory": str(directory_path),
            "excluded_paths": request.excluded_paths,
            "included_paths": request.included_paths,
            "result": formatted_result
        }
        analysis_history.append(history_entry)
        
        # Keep only last 20 analyses in memory
        if len(analysis_history) > 20:
            analysis_history.pop(0)
        
        return AnalysisResult(
            success=True,
            message="Analysis completed successfully",
            analysis_data=formatted_result
        )
    
    except Exception as e:
        return AnalysisResult(
            success=False,
            message=f"Analysis failed: {str(e)}"
        )


@app.get("/api/analysis-result")
async def get_analysis_result():
    """Get the current analysis result."""
    if current_analysis_state["analysis_result"] is None:
        raise HTTPException(status_code=404, detail="No analysis result available")
    
    result = current_analysis_state["analysis_result"]
    return JSONResponse(content={
        "success": True,
        "analysis_data": result.to_dict() if hasattr(result, 'to_dict') else str(result),
        "directory": current_analysis_state["directory"],
        "excluded_paths": current_analysis_state["excluded_paths"]
    })


@app.post("/api/export-analysis")
async def export_analysis(format: str = Form(...)):
    """Export analysis results in the specified format."""
    if current_analysis_state["analysis_result"] is None:
        raise HTTPException(status_code=404, detail="No analysis result available")
    
    try:
        result = current_analysis_state["analysis_result"]
        config = current_analysis_state["config"]
        
        if format == "json":
            # Export as JSON
            output_path = Path(current_analysis_state["directory"]) / "analysis_result.json"
            with open(output_path, 'w') as f:
                json.dump(result.to_dict() if hasattr(result, 'to_dict') else str(result), f, indent=2)
        
        elif format == "markdown":
            # Export as Markdown
            output_path = Path(current_analysis_state["directory"]) / "analysis_result.md"
            with open(output_path, 'w') as f:
                f.write("# Code Analysis Result\n\n")
                f.write(f"**Directory:** {current_analysis_state['directory']}\n\n")
                f.write(f"**Excluded Paths:** {', '.join(current_analysis_state['excluded_paths'])}\n\n")
                f.write("## Analysis\n\n")
                f.write(str(result))
        
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")
        
        return AnalysisResult(
            success=True,
            message=f"Analysis exported to {output_path}",
            file_path=str(output_path)
        )
    
    except Exception as e:
        return AnalysisResult(
            success=False,
            message=f"Export failed: {str(e)}"
        )


@app.post("/api/update-exclusions")
async def update_exclusions(excluded_paths: List[str]):
    """Update the list of excluded paths."""
    current_analysis_state["excluded_paths"] = excluded_paths
    return {"success": True, "excluded_paths": excluded_paths}


@app.get("/api/current-state")
async def get_current_state():
    """Get the current analysis state."""
    return JSONResponse(content={
        "directory": current_analysis_state["directory"],
        "excluded_paths": current_analysis_state["excluded_paths"],
        "has_result": current_analysis_state["analysis_result"] is not None
    })


@app.get("/api/analysis-history")
async def get_analysis_history():
    """Get the analysis history."""
    return JSONResponse(content={
        "history": analysis_history,
        "total": len(analysis_history)
    })


@app.get("/api/analysis-history/{analysis_id}")
async def get_analysis_by_id(analysis_id: int):
    """Get a specific analysis by ID."""
    for entry in analysis_history:
        if entry["id"] == analysis_id:
            return JSONResponse(content=entry)
    
    raise HTTPException(status_code=404, detail="Analysis not found")


@app.delete("/api/analysis-history/{analysis_id}")
async def delete_analysis(analysis_id: int):
    """Delete a specific analysis by ID."""
    global analysis_history
    
    for i, entry in enumerate(analysis_history):
        if entry["id"] == analysis_id:
            deleted_entry = analysis_history.pop(i)
            return JSONResponse(content={
                "success": True,
                "message": f"Deleted analysis {analysis_id}",
                "deleted": deleted_entry
            })
    
    raise HTTPException(status_code=404, detail="Analysis not found")


@app.delete("/api/analysis-history")
async def clear_analysis_history():
    """Clear all analysis history."""
    global analysis_history
    count = len(analysis_history)
    analysis_history = []
    
    return JSONResponse(content={
        "success": True,
        "message": f"Cleared {count} analysis entries",
        "cleared": count
    })


def build_file_tree(directory: Path, excluded_paths: List[str] = None) -> Dict[str, Any]:
    """Build a file tree structure for the given directory."""
    if excluded_paths is None:
        excluded_paths = current_analysis_state.get("excluded_paths", [])
    
    def should_exclude(path: Path) -> bool:
        """Check if a path should be excluded."""
        path_str = str(path)
        for excluded in excluded_paths:
            if excluded in path_str or path_str.startswith(excluded):
                return True
        return False
    
    def build_node(path: Path) -> Dict[str, Any]:
        """Build a tree node for a file or directory."""
        is_file = path.is_file()
        is_excluded = should_exclude(path)
        
        node = {
            "id": str(path),  # Unique identifier
            "name": path.name,
            "path": str(path),
            "is_file": is_file,
            "is_excluded": is_excluded,
            "is_expanded": False,  # For UI collapsing
            "has_children": False
        }
        
        if is_file:
            try:
                stat = path.stat()
                node["size"] = stat.st_size
                node["modified"] = stat.st_mtime
            except (OSError, IOError):
                node["size"] = None
                node["modified"] = None
        else:
            # Directory
            node["children"] = []
            child_count = 0
            try:
                children = []
                for child in sorted(path.iterdir()):
                    # Skip hidden files and common build directories by default
                    if child.name.startswith('.') or child.name in ['__pycache__', 'node_modules', '.git', '.venv', 'venv']:
                        continue
                    children.append(build_node(child))
                    child_count += 1
                
                node["children"] = children
                node["has_children"] = child_count > 0
                node["child_count"] = child_count
            except (OSError, IOError):
                pass  # Permission denied or other issues
        
        return node
    
    return build_node(directory)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
