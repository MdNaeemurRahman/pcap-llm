from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
from typing import Optional
import shutil
import os
from pathlib import Path

from .config import settings
from .modules.supabase_client import SupabaseManager
from .modules.virustotal_client import VirusTotalClient
from .modules.ollama_client import OllamaClient
from .modules.vector_store import VectorStoreManager
from .modules.pipeline import AnalysisPipeline
from .modules.chat_handler import ChatHandler
from .modules.cleanup_manager import CleanupManager

app = FastAPI(title="PCAP LLM Analyzer", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

supabase_manager = SupabaseManager(settings.supabase_url, settings.supabase_key)
vt_client = VirusTotalClient(settings.virustotal_api_key)
ollama_client = OllamaClient(
    settings.ollama_base_url,
    settings.ollama_embedding_model,
    settings.ollama_llm_model
)
vector_store = VectorStoreManager(
    persist_directory=str(settings.vector_db_dir),
    ollama_base_url=settings.ollama_base_url,
    embedding_model=settings.ollama_embedding_model
)

pipeline = AnalysisPipeline(
    supabase_manager=supabase_manager,
    vt_client=vt_client,
    ollama_client=ollama_client,
    vector_store=vector_store,
    uploads_dir=str(settings.uploads_dir),
    json_outputs_dir=str(settings.json_outputs_dir)
)

chat_handler = ChatHandler(
    ollama_client=ollama_client,
    vector_store=vector_store,
    supabase_manager=supabase_manager,
    json_outputs_dir=str(settings.json_outputs_dir)
)

cleanup_manager = CleanupManager(
    vector_store=vector_store,
    supabase_manager=supabase_manager,
    uploads_dir=str(settings.uploads_dir),
    json_outputs_dir=str(settings.json_outputs_dir)
)

frontend_dir = settings.base_dir / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")


class AnalyzeRequest(BaseModel):
    file_hash: str
    mode: str


class ChatRequest(BaseModel):
    analysis_id: str
    query: str


class CleanupRequest(BaseModel):
    days: Optional[int] = 30


@app.get("/")
async def read_root():
    index_file = frontend_dir / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "PCAP LLM Analyzer API", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    health_status = {
        "api": "healthy",
        "supabase": "unknown",
        "ollama": "unknown",
        "virustotal": "configured" if settings.virustotal_api_key else "not configured",
        "vector_store": "unknown"
    }

    try:
        supabase_manager.client.table('pcap_analyses').select('id').limit(1).execute()
        health_status["supabase"] = "healthy"
    except Exception as e:
        health_status["supabase"] = f"error: {str(e)}"

    if ollama_client.validate_connection():
        health_status["ollama"] = "healthy"
    else:
        health_status["ollama"] = "unreachable"

    vector_health = vector_store.health_check()
    health_status["vector_store"] = vector_health

    return health_status


@app.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith(('.pcap', '.pcapng', '.cap')):
        raise HTTPException(status_code=400, detail="Invalid file type. Only PCAP files are allowed.")

    try:
        from .modules.pcap_parser import PCAPParser

        file_path = settings.uploads_dir / file.filename
        with open(file_path, 'wb') as buffer:
            shutil.copyfileobj(file.file, buffer)

        parser = PCAPParser(str(file_path))
        file_hash = parser.compute_file_hash()

        existing_analysis = supabase_manager.get_analysis_by_hash(file_hash)
        if existing_analysis:
            return JSONResponse({
                "message": "PCAP file already analyzed",
                "analysis_id": existing_analysis['id'],
                "status": existing_analysis['status'],
                "existing": True,
                "filename": file.filename,
                "file_hash": file_hash
            })

        return JSONResponse({
            "message": "File uploaded successfully",
            "filename": file.filename,
            "file_hash": file_hash,
            "file_path": str(file_path)
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error uploading file: {str(e)}")


@app.post("/analyze")
async def analyze_pcap(request: AnalyzeRequest, background_tasks: BackgroundTasks):
    if request.mode not in ['option1', 'option2']:
        raise HTTPException(status_code=400, detail="Invalid analysis mode. Choose 'option1' or 'option2'.")

    try:
        file_hash = request.file_hash

        # Check if analysis already exists for this file hash
        existing_analysis = supabase_manager.get_analysis_by_hash(file_hash)
        if existing_analysis:
            if existing_analysis['status'] == 'ready':
                return JSONResponse({
                    "message": "Analysis already completed",
                    "analysis_id": existing_analysis['id'],
                    "status": "ready"
                })
            elif existing_analysis['status'] in ['parsing', 'enriching', 'embedding', 'uploaded']:
                return JSONResponse({
                    "message": "Analysis in progress",
                    "analysis_id": existing_analysis['id'],
                    "status": existing_analysis['status']
                })

        # Find the PCAP file with matching hash
        pcap_files = list(settings.uploads_dir.glob("*.pcap")) + \
                     list(settings.uploads_dir.glob("*.pcapng")) + \
                     list(settings.uploads_dir.glob("*.cap"))

        file_path = None
        filename = None
        for pcap_file in pcap_files:
            from .modules.pcap_parser import PCAPParser
            parser = PCAPParser(str(pcap_file))
            if parser.compute_file_hash() == file_hash:
                file_path = str(pcap_file)
                filename = pcap_file.name
                break

        if not file_path:
            raise HTTPException(status_code=404, detail="PCAP file not found. Please upload the file first.")

        # Create new analysis record
        analysis_id = supabase_manager.insert_analysis_record(
            filename=filename,
            file_hash=file_hash,
            analysis_mode=request.mode
        )

        if not analysis_id:
            raise HTTPException(status_code=500, detail="Failed to create analysis record in database")

        # Start background processing
        if request.mode == 'option1':
            background_tasks.add_task(
                pipeline.process_option1,
                file_path, filename, analysis_id
            )
        else:
            background_tasks.add_task(
                pipeline.process_option2,
                file_path, filename, analysis_id
            )

        return JSONResponse({
            "message": "Analysis started",
            "analysis_id": analysis_id,
            "mode": request.mode,
            "status": "processing"
        })

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting analysis: {str(e)}")


@app.get("/status/{analysis_id}")
async def get_status(analysis_id: str):
    try:
        analysis = supabase_manager.get_analysis_by_id(analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")

        return JSONResponse({
            "analysis_id": analysis_id,
            "status": analysis['status'],
            "mode": analysis['analysis_mode'],
            "filename": analysis['filename'],
            "total_packets": analysis['total_packets'],
            "unique_ips_count": analysis['unique_ips_count'],
            "unique_domains_count": analysis['unique_domains_count'],
            "created_at": analysis['created_at'],
            "updated_at": analysis['updated_at']
        })

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting status: {str(e)}")


@app.post("/chat")
async def chat_query(request: ChatRequest):
    try:
        analysis = supabase_manager.get_analysis_by_id(request.analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")

        if analysis['status'] != 'ready':
            raise HTTPException(
                status_code=400,
                detail=f"Analysis is not ready for queries. Current status: {analysis['status']}"
            )

        if analysis['analysis_mode'] == 'option1':
            result = chat_handler.handle_option1_query(request.analysis_id, request.query)
        else:
            result = chat_handler.handle_option2_query(request.analysis_id, request.query)

        if result['status'] == 'error':
            raise HTTPException(status_code=500, detail=result['message'])

        return JSONResponse({
            "analysis_id": request.analysis_id,
            "query": request.query,
            "response": result['response'],
            "mode": result['mode'],
            "retrieved_chunks": result.get('retrieved_chunks', None)
        })

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing chat query: {str(e)}")


@app.get("/analysis/{analysis_id}/results")
async def get_analysis_results(analysis_id: str):
    try:
        results = pipeline.get_analysis_results(analysis_id)
        if not results:
            raise HTTPException(status_code=404, detail="Analysis not found")

        return JSONResponse(results)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting results: {str(e)}")


@app.get("/analyses")
async def list_analyses(limit: int = 50, offset: int = 0):
    try:
        analyses = supabase_manager.list_user_analyses(limit=limit, offset=offset)
        return JSONResponse({"analyses": analyses, "count": len(analyses)})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing analyses: {str(e)}")


@app.get("/analysis/{analysis_id}/chat_history")
async def get_chat_history(analysis_id: str):
    try:
        history = chat_handler.get_chat_history(analysis_id)
        return JSONResponse({"analysis_id": analysis_id, "history": history})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting chat history: {str(e)}")


@app.post("/admin/cleanup")
async def cleanup_old_data(days: int = 30):
    try:
        results = cleanup_manager.cleanup_old_analyses(days)
        return JSONResponse(results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during cleanup: {str(e)}")


@app.post("/admin/cleanup/failed")
async def cleanup_failed():
    try:
        results = cleanup_manager.cleanup_failed_analyses()
        return JSONResponse(results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error cleaning failed analyses: {str(e)}")


@app.post("/admin/vacuum")
async def vacuum_vector_db():
    try:
        results = cleanup_manager.vacuum_vector_database()
        return JSONResponse(results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error vacuuming vector database: {str(e)}")


@app.get("/admin/storage/stats")
async def get_storage_stats():
    try:
        stats = cleanup_manager.get_storage_stats()
        return JSONResponse(stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting storage stats: {str(e)}")


@app.post("/reanalyze")
async def reanalyze_pcap(request: AnalyzeRequest, background_tasks: BackgroundTasks):
    if request.mode not in ['option1', 'option2']:
        raise HTTPException(status_code=400, detail="Invalid analysis mode. Choose 'option1' or 'option2'.")

    try:
        file_hash = request.file_hash

        existing_analysis = supabase_manager.get_analysis_by_hash(file_hash)
        if existing_analysis:
            analysis_id = existing_analysis['id']
            print(f"Re-analyzing existing analysis: {analysis_id}")

            success = cleanup_manager.delete_specific_analysis(analysis_id)
            if not success:
                print(f"Warning: Could not fully clean up previous analysis {analysis_id}")

        pcap_files = list(settings.uploads_dir.glob("*.pcap")) + \
                     list(settings.uploads_dir.glob("*.pcapng")) + \
                     list(settings.uploads_dir.glob("*.cap"))

        file_path = None
        filename = None
        for pcap_file in pcap_files:
            from .modules.pcap_parser import PCAPParser
            parser = PCAPParser(str(pcap_file))
            if parser.compute_file_hash() == file_hash:
                file_path = str(pcap_file)
                filename = pcap_file.name
                break

        if not file_path:
            raise HTTPException(status_code=404, detail="PCAP file not found. Please upload the file first.")

        new_analysis_id = supabase_manager.insert_analysis_record(
            filename=filename,
            file_hash=file_hash,
            analysis_mode=request.mode
        )

        if not new_analysis_id:
            raise HTTPException(status_code=500, detail="Failed to create analysis record in database")

        if request.mode == 'option1':
            background_tasks.add_task(
                pipeline.process_option1,
                file_path, filename, new_analysis_id
            )
        else:
            background_tasks.add_task(
                pipeline.process_option2,
                file_path, filename, new_analysis_id
            )

        return JSONResponse({
            "message": "Re-analysis started",
            "analysis_id": new_analysis_id,
            "mode": request.mode,
            "status": "processing"
        })

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting re-analysis: {str(e)}")


@app.delete("/analysis/{analysis_id}")
async def delete_analysis(analysis_id: str):
    try:
        success = cleanup_manager.delete_specific_analysis(analysis_id)
        if success:
            return JSONResponse({"message": "Analysis deleted successfully", "analysis_id": analysis_id})
        else:
            raise HTTPException(status_code=404, detail="Analysis not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting analysis: {str(e)}")


@app.get("/admin/collections")
async def list_collections():
    try:
        collections = vector_store.list_collections()
        return JSONResponse({"collections": collections})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing collections: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
