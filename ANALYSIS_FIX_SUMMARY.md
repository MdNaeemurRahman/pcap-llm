# Analysis Flow Fix Summary

## Issues Fixed

### 1. Invalid analysis_id Format Error
**Problem**: The frontend was sending `file_hash` as `analysis_id`, but the backend expected a UUID and tried to parse it with string splitting.

**Solution**: 
- Changed the `/analyze` endpoint to accept `file_hash` directly instead of `analysis_id`
- Updated the request model from `AnalyzeRequest.analysis_id` to `AnalyzeRequest.file_hash`
- Simplified the analysis lookup logic to use the file hash to check for existing analyses
- The backend now creates a new analysis record and returns the proper UUID

### 2. Network Connectivity Error (DNS Resolution)
**Problem**: The application showed `[Errno -2] Name or service not known` errors when trying to connect to Supabase.

**Solution**:
- Added DNS resolution check before creating the Supabase client
- Implemented connection retry logic (3 attempts with 2-second delays)
- Enhanced error messages to distinguish between DNS issues, connection failures, and API errors
- Added specific error handling for `socket.gaierror` and `ConnectionError` exceptions

## Files Modified

### 1. `/app/main.py`
- Changed `AnalyzeRequest` model to use `file_hash` instead of `analysis_id`
- Rewrote the `/analyze` endpoint logic to:
  - Accept file_hash directly from the frontend
  - Check for existing analysis by hash first
  - Find the uploaded PCAP file by computing hashes
  - Create a new analysis record in the database
  - Return the proper UUID analysis_id
- Added better error handling with HTTP exception propagation

### 2. `/frontend/index.html`
- Updated the analyze button click handler to send `file_hash` instead of `analysis_id`
- Changed the fetch request body from `{ analysis_id: currentFileHash, mode: mode }` to `{ file_hash: currentFileHash, mode: mode }`

### 3. `/app/modules/supabase_client.py`
- Added imports for `socket` and `time` modules
- Enhanced `__init__` method with:
  - Pre-flight DNS resolution check
  - Detailed error messages for DNS failures
  - Connection retry logic (3 attempts)
  - Success confirmation message
- Improved error handling in `get_analysis_by_id()` and `get_analysis_by_hash()`:
  - Separate handling for DNS errors (`socket.gaierror`)
  - Separate handling for connection errors (`ConnectionError`)
  - More descriptive error messages

## Testing Verification

To verify the fix works:

1. **Upload a PCAP file**:
   - The upload should complete successfully and return a file_hash
   
2. **Start Analysis**:
   - Select either Option 1 or Option 2
   - Click "Start Analysis"
   - The frontend now sends: `{ file_hash: "abc123...", mode: "option1" }`
   - The backend receives the file_hash, finds the file, creates an analysis record
   - Returns a proper UUID analysis_id

3. **Monitor Status**:
   - Status polling should work with the UUID analysis_id
   - No more "Invalid analysis_id format" errors

## Network Troubleshooting

If DNS errors still occur:

1. Check internet connectivity:
   ```bash
   python3 -c "import socket; print(socket.gethostbyname('cgbtfubcjqyqsliixyzm.supabase.co'))"
   ```

2. Test HTTPS connectivity:
   ```bash
   curl -I https://cgbtfubcjqyqsliixyzm.supabase.co
   ```

3. Verify firewall settings allow outbound HTTPS traffic

4. Check if a proxy is required in your environment

## Expected Behavior

- ✅ File upload returns file_hash
- ✅ Analysis endpoint accepts file_hash and creates analysis record
- ✅ Returns UUID analysis_id for status tracking
- ✅ Better error messages for network issues
- ✅ Automatic retry on transient connection failures
- ✅ Clear distinction between DNS, connection, and API errors
