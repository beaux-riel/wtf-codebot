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
    "analysis_result": None,
    "config": None
}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the main web interface."""
    return templates.TemplateResponse("index.html", {"request": request})


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
        return JSONResponse(content=tree)
    
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
        
        # Create config with exclusions  
        from wtf_codebot.core.config import get_config
        config = get_config()
        
        # Override with request parameters
        if request.excluded_paths:
            config.analysis.exclude_patterns.extend(request.excluded_paths)
        
        current_analysis_state["config"] = config
        
        # Run analysis
        analyzer = AnalysisEngine(config)
        analysis_result = analyzer.analyze(directory_path)
        
        # Store result
        current_analysis_state["analysis_result"] = analysis_result
        
        return AnalysisResult(
            success=True,
            message="Analysis completed successfully",
            analysis_data=analysis_result.to_dict() if hasattr(analysis_result, 'to_dict') else None
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


def build_file_tree(directory: Path, excluded_paths: List[str] = None) -> Dict[str, Any]:
    """Build a file tree structure for the given directory."""
    if excluded_paths is None:
        excluded_paths = current_analysis_state["excluded_paths"]
    
    def should_exclude(path: Path) -> bool:
        """Check if a path should be excluded."""
        path_str = str(path)
        for excluded in excluded_paths:
            if excluded in path_str or path_str.startswith(excluded):
                return True
        return False
    
    def build_node(path: Path) -> Dict[str, Any]:
        """Build a tree node for a file or directory."""
        node = {
            "name": path.name,
            "path": str(path),
            "is_file": path.is_file(),
            "is_excluded": should_exclude(path)
        }
        
        if path.is_file():
            try:
                node["size"] = path.stat().st_size
            except (OSError, IOError):
                node["size"] = None
        else:
            # Directory
            node["children"] = []
            try:
                for child in sorted(path.iterdir()):
                    # Skip hidden files and common build directories
                    if child.name.startswith('.') or child.name in ['__pycache__', 'node_modules', '.git']:
                        continue
                    node["children"].append(build_node(child))
            except (OSError, IOError):
                pass  # Permission denied or other issues
        
        return node
    
    return build_node(directory)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
