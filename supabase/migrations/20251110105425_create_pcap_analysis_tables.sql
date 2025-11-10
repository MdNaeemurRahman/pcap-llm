/*
  # Create PCAP Analysis System Tables

  1. New Tables
    - `pcap_analyses`
      - `id` (uuid, primary key)
      - `filename` (text) - original PCAP filename
      - `file_hash` (text, unique) - SHA256 hash of the file
      - `upload_timestamp` (timestamptz) - when file was uploaded
      - `analysis_mode` (text) - 'option1' or 'option2'
      - `status` (text) - processing status
      - `total_packets` (integer) - total packet count
      - `top_protocols` (jsonb) - protocol distribution
      - `unique_ips_count` (integer) - count of unique IPs
      - `unique_domains_count` (integer) - count of unique domains
      - `created_at` (timestamptz)
      - `updated_at` (timestamptz)

    - `virustotal_results`
      - `id` (uuid, primary key)
      - `analysis_id` (uuid, foreign key) - references pcap_analyses
      - `entity_type` (text) - 'ip', 'domain', or 'file'
      - `entity_value` (text) - the IP/domain/hash value
      - `malicious_count` (integer) - number of engines flagging as malicious
      - `last_analysis_stats` (jsonb) - full stats from VirusTotal
      - `category` (text) - VirusTotal category
      - `queried_at` (timestamptz) - when query was made
      - `created_at` (timestamptz)

    - `chat_sessions`
      - `id` (uuid, primary key)
      - `analysis_id` (uuid, foreign key) - references pcap_analyses
      - `user_query` (text) - the question asked
      - `llm_response` (text) - the LLM's answer
      - `retrieved_chunks` (jsonb) - chunks used for Option 2 RAG
      - `timestamp` (timestamptz)

    - `chunks_metadata`
      - `id` (uuid, primary key)
      - `analysis_id` (uuid, foreign key) - references pcap_analyses
      - `chunk_index` (integer) - order of chunk
      - `chunk_text` (text) - the chunk content
      - `ip_addresses` (jsonb) - IPs in this chunk
      - `domains` (jsonb) - domains in this chunk
      - `timestamp_range` (jsonb) - start/end timestamps
      - `created_at` (timestamptz)

  2. Security
    - Enable RLS on all tables
    - Add policies for authenticated access
    - Create indexes for performance

  3. Important Notes
    - All tables use uuid primary keys with auto-generation
    - Timestamps default to now()
    - Foreign keys enforce referential integrity
    - Indexes on frequently queried fields
*/

-- Create pcap_analyses table
CREATE TABLE IF NOT EXISTS pcap_analyses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  filename text NOT NULL,
  file_hash text UNIQUE NOT NULL,
  upload_timestamp timestamptz DEFAULT now(),
  analysis_mode text NOT NULL CHECK (analysis_mode IN ('option1', 'option2')),
  status text DEFAULT 'uploaded' CHECK (status IN ('uploaded', 'parsing', 'enriching', 'embedding', 'ready', 'failed')),
  total_packets integer DEFAULT 0,
  top_protocols jsonb DEFAULT '{}',
  unique_ips_count integer DEFAULT 0,
  unique_domains_count integer DEFAULT 0,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- Create virustotal_results table
CREATE TABLE IF NOT EXISTS virustotal_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_id uuid NOT NULL REFERENCES pcap_analyses(id) ON DELETE CASCADE,
  entity_type text NOT NULL CHECK (entity_type IN ('ip', 'domain', 'file')),
  entity_value text NOT NULL,
  malicious_count integer DEFAULT 0,
  last_analysis_stats jsonb DEFAULT '{}',
  category text,
  queried_at timestamptz DEFAULT now(),
  created_at timestamptz DEFAULT now()
);

-- Create chat_sessions table
CREATE TABLE IF NOT EXISTS chat_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_id uuid NOT NULL REFERENCES pcap_analyses(id) ON DELETE CASCADE,
  user_query text NOT NULL,
  llm_response text NOT NULL,
  retrieved_chunks jsonb DEFAULT '[]',
  timestamp timestamptz DEFAULT now()
);

-- Create chunks_metadata table
CREATE TABLE IF NOT EXISTS chunks_metadata (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_id uuid NOT NULL REFERENCES pcap_analyses(id) ON DELETE CASCADE,
  chunk_index integer NOT NULL,
  chunk_text text NOT NULL,
  ip_addresses jsonb DEFAULT '[]',
  domains jsonb DEFAULT '[]',
  timestamp_range jsonb DEFAULT '{}',
  created_at timestamptz DEFAULT now()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_pcap_analyses_file_hash ON pcap_analyses(file_hash);
CREATE INDEX IF NOT EXISTS idx_pcap_analyses_status ON pcap_analyses(status);
CREATE INDEX IF NOT EXISTS idx_pcap_analyses_created_at ON pcap_analyses(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_virustotal_results_analysis_id ON virustotal_results(analysis_id);
CREATE INDEX IF NOT EXISTS idx_virustotal_results_entity_value ON virustotal_results(entity_value);
CREATE INDEX IF NOT EXISTS idx_virustotal_results_malicious ON virustotal_results(malicious_count) WHERE malicious_count > 0;

CREATE INDEX IF NOT EXISTS idx_chat_sessions_analysis_id ON chat_sessions(analysis_id);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_timestamp ON chat_sessions(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_chunks_metadata_analysis_id ON chunks_metadata(analysis_id);
CREATE INDEX IF NOT EXISTS idx_chunks_metadata_chunk_index ON chunks_metadata(analysis_id, chunk_index);

-- Enable Row Level Security
ALTER TABLE pcap_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE virustotal_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE chunks_metadata ENABLE ROW LEVEL SECURITY;

-- Create policies for public access (since this is a local tool)
CREATE POLICY "Allow all operations on pcap_analyses"
  ON pcap_analyses FOR ALL
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Allow all operations on virustotal_results"
  ON virustotal_results FOR ALL
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Allow all operations on chat_sessions"
  ON chat_sessions FOR ALL
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Allow all operations on chunks_metadata"
  ON chunks_metadata FOR ALL
  USING (true)
  WITH CHECK (true);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for pcap_analyses
DROP TRIGGER IF EXISTS update_pcap_analyses_updated_at ON pcap_analyses;
CREATE TRIGGER update_pcap_analyses_updated_at
  BEFORE UPDATE ON pcap_analyses
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();
