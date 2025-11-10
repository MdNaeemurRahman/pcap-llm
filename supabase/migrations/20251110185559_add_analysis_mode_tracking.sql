/*
  # Add Analysis Mode State Tracking

  1. Changes to pcap_analyses table
    - Add `current_mode` column to track which analysis mode is currently active
    - This enables detecting when users switch between option1 and option2
    - Allows smart re-processing that reuses existing data when appropriate

  2. Purpose
    - Track which mode (option1 or option2) was used for the current ready state
    - Enable mode transition detection to trigger appropriate re-processing
    - Preserve VirusTotal data across mode switches to avoid redundant API calls
*/

-- Add current_mode column to track active analysis mode
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'pcap_analyses' AND column_name = 'current_mode'
  ) THEN
    ALTER TABLE pcap_analyses ADD COLUMN current_mode text;
    
    -- Update existing records to match their analysis_mode
    UPDATE pcap_analyses SET current_mode = analysis_mode WHERE current_mode IS NULL;
    
    -- Add check constraint to ensure valid values
    ALTER TABLE pcap_analyses ADD CONSTRAINT valid_current_mode CHECK (current_mode IN ('option1', 'option2'));
  END IF;
END $$;