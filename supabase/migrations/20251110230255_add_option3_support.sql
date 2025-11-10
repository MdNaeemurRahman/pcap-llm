/*
  # Add Option 3 Support to Analysis Mode Constraints

  1. Changes to pcap_analyses table
    - Update `analysis_mode` CHECK constraint to include 'option3'
    - Update `current_mode` CHECK constraint to include 'option3'
    - This enables the new Agentic TShark analysis mode

  2. Purpose
    - Allow users to select option3 (Agentic TShark) as a valid analysis mode
    - Fix constraint violations when switching to option3 mode
    - Maintain backward compatibility with existing option1 and option2 records

  3. Important Notes
    - Drops and recreates CHECK constraints safely
    - No data loss - only constraint modification
    - Existing records remain unchanged
*/

-- Drop existing CHECK constraints if they exist
DO $$
BEGIN
  -- Drop analysis_mode constraint
  IF EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'pcap_analyses_analysis_mode_check'
    AND table_name = 'pcap_analyses'
  ) THEN
    ALTER TABLE pcap_analyses DROP CONSTRAINT pcap_analyses_analysis_mode_check;
  END IF;

  -- Drop current_mode constraint  
  IF EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'valid_current_mode'
    AND table_name = 'pcap_analyses'
  ) THEN
    ALTER TABLE pcap_analyses DROP CONSTRAINT valid_current_mode;
  END IF;
END $$;

-- Add updated CHECK constraints that include option3
ALTER TABLE pcap_analyses 
  ADD CONSTRAINT pcap_analyses_analysis_mode_check 
  CHECK (analysis_mode IN ('option1', 'option2', 'option3'));

ALTER TABLE pcap_analyses 
  ADD CONSTRAINT valid_current_mode 
  CHECK (current_mode IN ('option1', 'option2', 'option3'));

-- Update any NULL current_mode values to match analysis_mode
UPDATE pcap_analyses 
SET current_mode = analysis_mode 
WHERE current_mode IS NULL;
