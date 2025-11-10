/*
  # Add Enhanced File Hash Detection Fields

  1. Schema Changes
    - Add fields to `virustotal_results` table for comprehensive file hash analysis:
      - `file_type` (text) - Type of file detected
      - `file_size` (bigint) - Size of the file in bytes
      - `threat_label` (text) - Suggested threat label from VirusTotal
      - `threat_category` (jsonb) - Array of threat categories
      - `detection_engines` (jsonb) - Array of detection engine results
      - `sandbox_verdicts` (jsonb) - Sandbox analysis verdicts
      - `md5` (text) - MD5 hash of the file
      - `sha1` (text) - SHA1 hash of the file
      - `sha256` (text) - SHA256 hash of the file
      - `first_submission_date` (timestamptz) - First time file was seen
      - `last_analysis_date` (timestamptz) - Most recent analysis

  2. Important Notes
    - These fields are optional and only populated for file entity types
    - Backward compatible with existing data
    - Enables detailed malware analysis and classification
*/

-- Add file hash specific fields to virustotal_results
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'file_type'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN file_type text;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'file_size'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN file_size bigint;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'threat_label'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN threat_label text;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'threat_category'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN threat_category jsonb DEFAULT '[]';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'detection_engines'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN detection_engines jsonb DEFAULT '[]';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'sandbox_verdicts'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN sandbox_verdicts jsonb DEFAULT '[]';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'md5'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN md5 text;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'sha1'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN sha1 text;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'sha256'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN sha256 text;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'first_submission_date'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN first_submission_date timestamptz;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'last_analysis_date'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN last_analysis_date timestamptz;
  END IF;
END $$;

-- Create index for file hash lookups
CREATE INDEX IF NOT EXISTS idx_virustotal_results_sha256 ON virustotal_results(sha256) WHERE entity_type = 'file';
CREATE INDEX IF NOT EXISTS idx_virustotal_results_file_type ON virustotal_results(entity_type) WHERE entity_type = 'file';
