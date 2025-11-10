/*
  # Add VirusTotal Count Fields to virustotal_results

  1. Schema Changes
    - Add missing count fields to `virustotal_results` table:
      - `suspicious_count` (integer) - Number of engines flagging as suspicious
      - `harmless_count` (integer) - Number of engines flagging as harmless
      - `undetected_count` (integer) - Number of engines not detecting anything
      - `reputation` (integer) - Reputation score from VirusTotal

  2. Data Backfill
    - Extract count values from existing `last_analysis_stats` JSONB field
    - Update all existing records with the extracted values
    - Ensures backward compatibility with cached data

  3. Indexes
    - Add index on suspicious_count for efficient querying of suspicious entities

  4. Important Notes
    - These fields were previously only stored in the last_analysis_stats JSONB
    - Making them top-level columns fixes KeyError when accessing cached results
    - The migration is idempotent and safe to run multiple times
*/

-- Add count fields to virustotal_results
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'suspicious_count'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN suspicious_count integer DEFAULT 0;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'harmless_count'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN harmless_count integer DEFAULT 0;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'undetected_count'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN undetected_count integer DEFAULT 0;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'virustotal_results' AND column_name = 'reputation'
  ) THEN
    ALTER TABLE virustotal_results ADD COLUMN reputation integer DEFAULT 0;
  END IF;
END $$;

-- Backfill existing records with data from last_analysis_stats JSONB
UPDATE virustotal_results
SET
  suspicious_count = COALESCE((last_analysis_stats->>'suspicious')::integer, 0),
  harmless_count = COALESCE((last_analysis_stats->>'harmless')::integer, 0),
  undetected_count = COALESCE((last_analysis_stats->>'undetected')::integer, 0)
WHERE suspicious_count IS NULL OR harmless_count IS NULL OR undetected_count IS NULL;

-- Create index for suspicious entity queries
CREATE INDEX IF NOT EXISTS idx_virustotal_results_suspicious
  ON virustotal_results(suspicious_count)
  WHERE suspicious_count > 0;

-- Create composite index for flagged entities (malicious OR suspicious)
CREATE INDEX IF NOT EXISTS idx_virustotal_results_flagged
  ON virustotal_results(analysis_id, malicious_count, suspicious_count)
  WHERE malicious_count > 0 OR suspicious_count > 0;
