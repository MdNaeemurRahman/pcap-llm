/*
  # Add PCAP File Path for Option 3 Support

  1. Changes
    - Add `pcap_file_path` column to `pcap_analyses` table to store the original PCAP file location
    - This enables Option 3's agentic TShark functionality to execute dynamic queries on the original file

  2. Purpose
    - Option 3 (Agentic TShark Mode) needs access to the original PCAP file for on-demand analysis
    - Unlike Option 1 (summary) and Option 2 (RAG), Option 3 runs TShark commands dynamically based on user queries
    - Storing the file path allows the system to execute custom TShark filters without keeping full packet data in database

  3. Important Notes
    - This field is optional and only populated for Option 3 analyses
    - The path must be accessible from the application server
    - File path security is handled at the application layer
*/

-- Add pcap_file_path column to store original PCAP file location for Option 3 TShark queries
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'pcap_analyses' AND column_name = 'pcap_file_path'
  ) THEN
    ALTER TABLE pcap_analyses ADD COLUMN pcap_file_path text;
    COMMENT ON COLUMN pcap_analyses.pcap_file_path IS 'Path to original PCAP file for Option 3 agentic TShark queries';
  END IF;
END $$;