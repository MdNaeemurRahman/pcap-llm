/*
  # Add missing columns to chunks_metadata table

  1. Changes
    - Add `vector_collection_name` column to track which ChromaDB collection the chunk belongs to
    - Add `chunk_hash` column to store SHA256 hash of chunk text for deduplication
    - Add `chunk_size` column to track the size of chunk text
    - Add `has_threat_intelligence` boolean flag to mark chunks containing VirusTotal threat data
    - Add `chunk_type` column to distinguish between 'packet_data' and 'threat_intelligence' chunks
    
  2. Notes
    - All columns are added with IF NOT EXISTS checks to avoid errors
    - Default values are provided for existing rows
    - New columns are nullable to support existing data
*/

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'chunks_metadata' AND column_name = 'vector_collection_name'
  ) THEN
    ALTER TABLE chunks_metadata ADD COLUMN vector_collection_name text;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'chunks_metadata' AND column_name = 'chunk_hash'
  ) THEN
    ALTER TABLE chunks_metadata ADD COLUMN chunk_hash text;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'chunks_metadata' AND column_name = 'chunk_size'
  ) THEN
    ALTER TABLE chunks_metadata ADD COLUMN chunk_size integer DEFAULT 0;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'chunks_metadata' AND column_name = 'has_threat_intelligence'
  ) THEN
    ALTER TABLE chunks_metadata ADD COLUMN has_threat_intelligence boolean DEFAULT false;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'chunks_metadata' AND column_name = 'chunk_type'
  ) THEN
    ALTER TABLE chunks_metadata ADD COLUMN chunk_type text DEFAULT 'packet_data';
  END IF;
END $$;

ALTER TABLE chunks_metadata 
  DROP CONSTRAINT IF EXISTS chunks_metadata_chunk_type_check;

ALTER TABLE chunks_metadata 
  ADD CONSTRAINT chunks_metadata_chunk_type_check 
  CHECK (chunk_type = ANY (ARRAY['packet_data'::text, 'threat_intelligence'::text]));