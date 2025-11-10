/*
  # Optimize chunks_metadata table for vector database architecture

  1. Changes
    - Remove chunk_text column from chunks_metadata table
    - Add vector_collection_name to track ChromaDB collection
    - Add chunk_hash for deduplication
    - Update indexes for optimized queries
    - Keep only metadata references in Supabase
    - Full text content stored in ChromaDB only

  2. Rationale
    - Eliminate duplicate storage between Supabase and ChromaDB
    - Reduce Supabase storage costs
    - Improve query performance by avoiding large text fields
    - Follow vector database best practices
    - ChromaDB is source of truth for embeddings and chunk text
    - Supabase stores only metadata and references

  3. Important Notes
    - Existing data will be preserved in chunks_metadata_backup
    - New chunks will not store full text in Supabase
    - Applications must retrieve text from ChromaDB when needed
    - This is a breaking change for queries that select chunk_text
*/

-- Create backup of existing chunks_metadata table
CREATE TABLE IF NOT EXISTS chunks_metadata_backup AS
SELECT * FROM chunks_metadata;

-- Drop the old chunk_text column (this removes duplicate storage)
ALTER TABLE chunks_metadata DROP COLUMN IF EXISTS chunk_text;

-- Add new columns for vector database integration
ALTER TABLE chunks_metadata ADD COLUMN IF NOT EXISTS vector_collection_name text;
ALTER TABLE chunks_metadata ADD COLUMN IF NOT EXISTS chunk_hash text;
ALTER TABLE chunks_metadata ADD COLUMN IF NOT EXISTS chunk_size integer DEFAULT 0;

-- Update the vector_collection_name for existing records
UPDATE chunks_metadata
SET vector_collection_name = 'pcap_' || analysis_id::text
WHERE vector_collection_name IS NULL;

-- Create index on vector collection name for fast lookups
CREATE INDEX IF NOT EXISTS idx_chunks_metadata_collection ON chunks_metadata(vector_collection_name);

-- Create index on chunk_hash for deduplication
CREATE INDEX IF NOT EXISTS idx_chunks_metadata_hash ON chunks_metadata(chunk_hash);

-- Add comment explaining the schema
COMMENT ON TABLE chunks_metadata IS 'Stores metadata references to chunks stored in ChromaDB. Full chunk text and embeddings are stored in ChromaDB vector database.';
COMMENT ON COLUMN chunks_metadata.vector_collection_name IS 'Name of ChromaDB collection containing the chunk embeddings and full text';
COMMENT ON COLUMN chunks_metadata.chunk_hash IS 'SHA256 hash of chunk content for deduplication';
COMMENT ON COLUMN chunks_metadata.chunk_size IS 'Size of chunk in characters';
