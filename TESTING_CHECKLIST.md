# Testing Checklist for Option 3 Enhancements & UI Improvements

## Pre-Testing Setup
- [ ] Ensure Ollama is running
- [ ] Ensure Supabase connection is active
- [ ] Upload a PCAP file with VirusTotal results
- [ ] Complete analysis in any mode to generate summary file

---

## Option 3 Intelligence Tests

### Test 1: Enhanced Greeting
**Steps:**
1. Upload PCAP and analyze with Option 3
2. Type "hi" or "hello" in chat

**Expected Result:**
```
Hello! I'm your AI security analyst...

**Quick Overview:**
- Total packets: [number]
- Unique IPs: [number]
- ⚠️ [number] malicious entities detected by VirusTotal (if threats exist)

What would you like to know about the captured packets?
```

**Status:** [ ] Pass [ ] Fail

---

### Test 2: Malicious IP Query (Summary-Based)
**Steps:**
1. Type: "which ip has malicious detections?"

**Expected Result:**
- Instant response (< 1 second)
- Lists malicious IPs with VirusTotal detection counts
- Shows threat types if available
- No TShark command execution visible

**Status:** [ ] Pass [ ] Fail

---

### Test 3: Protocol Query (Summary-Based)
**Steps:**
1. Type: "what protocols are in this capture?"

**Expected Result:**
- Instant response from summary
- Lists top 5 protocols with packet counts
- Formatted as a clean list

**Status:** [ ] Pass [ ] Fail

---

### Test 4: Threat Overview Query (Summary-Based)
**Steps:**
1. Type: "overall threats?" or "security summary"

**Expected Result:**
- Comprehensive threat summary
- Shows malicious/suspicious entity counts
- Breaks down by IPs, domains, and files
- All from VirusTotal data

**Status:** [ ] Pass [ ] Fail

---

### Test 5: Complex Query (TShark Execution)
**Steps:**
1. Type: "find communication session of this ip [specific IP]"

**Expected Result:**
- Takes 1-3 seconds (TShark execution time)
- Returns detailed analysis of IP communications
- Response references specific evidence (packet counts, timestamps)
- Natural conversational response (not mentioning commands)

**Status:** [ ] Pass [ ] Fail

---

### Test 6: Packet Count Query (Summary-Based)
**Steps:**
1. Type: "how many packets?" or "total packets"

**Expected Result:**
- Instant response
- Shows formatted packet count with commas
- Example: "This PCAP file contains **45,234** packets."

**Status:** [ ] Pass [ ] Fail

---

## Chat UI Tests (All Options)

### Test 7: Resizable Chat Window
**Steps:**
1. Load any analysis mode with chat active
2. Locate resize handle at bottom of chat messages area
3. Click and drag handle downward
4. Click and drag handle upward
5. Refresh the page

**Expected Result:**
- Resize handle visible with hover effect
- Chat height changes smoothly while dragging
- Minimum height enforced (300px)
- Maximum height enforced (80% viewport)
- After refresh, chat height is restored to last size

**Status:** [ ] Pass [ ] Fail

---

### Test 8: Loading States and Animations
**Steps:**
1. Submit a query in chat
2. Observe loading indicator
3. Wait for response
4. Submit another query

**Expected Result:**
- Randomized loading message appears ("Analyzing your query...", etc.)
- Animated spinner visible during processing
- Input field disabled during processing
- New messages fade in smoothly with slide-up animation
- Input automatically focused after response

**Status:** [ ] Pass [ ] Fail

---

### Test 9: Message Styling and Readability
**Steps:**
1. Ask a complex question that generates a long response with:
   - Multiple paragraphs
   - Bullet lists
   - Code blocks (if applicable)
   - Headings

**Expected Result:**
- Good spacing between paragraphs
- Lists are well-formatted with proper indentation
- Code blocks have dark theme and syntax highlighting
- Proper line height (1.6) for comfortable reading
- Message bubbles have adequate padding

**Status:** [ ] Pass [ ] Fail

---

### Test 10: Smooth Scrolling
**Steps:**
1. Fill chat with multiple messages (send 5-6 queries)
2. Observe scrolling behavior as new messages arrive
3. Manually scroll up, then send new message

**Expected Result:**
- Automatic smooth scroll to latest message
- No jarring jumps
- Smooth animation when auto-scrolling

**Status:** [ ] Pass [ ] Fail

---

### Test 11: localStorage Persistence
**Steps:**
1. Resize chat to a specific height (e.g., very tall)
2. Note the approximate height
3. Refresh the browser
4. Observe chat height
5. Clear browser localStorage
6. Refresh again

**Expected Result:**
- After first refresh: Height is restored to custom size
- After clearing localStorage and refresh: Height resets to default 550px

**Status:** [ ] Pass [ ] Fail

---

### Test 12: Responsive Behavior
**Steps:**
1. Test on desktop (full screen)
2. Resize browser window to tablet size
3. Resize to mobile size (if applicable)

**Expected Result:**
- Chat remains usable at all sizes
- Resize handle still functional
- Message bubbles adapt properly
- No horizontal scrolling

**Status:** [ ] Pass [ ] Fail

---

## Cross-Mode Consistency Tests

### Test 13: Option 1 UI Improvements
**Steps:**
1. Analyze PCAP with Option 1
2. Test resizable chat
3. Verify message styling
4. Test loading states

**Expected Result:**
- All UI improvements present
- Consistent with Option 2 and Option 3

**Status:** [ ] Pass [ ] Fail

---

### Test 14: Option 2 UI Improvements
**Steps:**
1. Analyze PCAP with Option 2
2. Test resizable chat
3. Verify message styling
4. Test loading states

**Expected Result:**
- All UI improvements present
- Consistent with Option 1 and Option 3

**Status:** [ ] Pass [ ] Fail

---

### Test 15: Option 3 UI Improvements
**Steps:**
1. Analyze PCAP with Option 3
2. Test resizable chat
3. Verify message styling
4. Test loading states

**Expected Result:**
- All UI improvements present
- Consistent with Option 1 and Option 2
- Plus enhanced intelligence features

**Status:** [ ] Pass [ ] Fail

---

## Edge Cases and Error Handling

### Test 16: Summary File Missing
**Steps:**
1. Manually delete summary JSON file
2. Try to chat in Option 3

**Expected Result:**
- Graceful error message
- Clear indication of missing summary file

**Status:** [ ] Pass [ ] Fail

---

### Test 17: TShark Not Available
**Steps:**
1. Ensure TShark is not installed
2. Try Option 3 with complex query

**Expected Result:**
- Clear installation instructions provided
- No crash or confusing error

**Status:** [ ] Pass [ ] Fail

---

### Test 18: Very Long Response
**Steps:**
1. Ask question that generates very long response
2. Observe chat behavior

**Expected Result:**
- Scrollbar appears in chat area
- Smooth scroll to bottom
- Message fully visible with no cutoff
- Resize still works properly

**Status:** [ ] Pass [ ] Fail

---

## Performance Tests

### Test 19: Summary-Based Response Speed
**Steps:**
1. Submit 5 different summary-based queries in sequence
2. Measure approximate response times

**Expected Result:**
- Each response under 500ms
- No TShark execution delays
- Smooth, instant-feeling responses

**Status:** [ ] Pass [ ] Fail

---

### Test 20: Mode Switching
**Steps:**
1. Analyze with Option 1
2. Switch to Option 3
3. Verify summary data available
4. Test greeting and queries

**Expected Result:**
- Summary data properly loaded in Option 3
- Enhanced greeting shows correct stats
- Summary-based queries work immediately

**Status:** [ ] Pass [ ] Fail

---

## Visual Quality Checks

### Test 21: Resize Handle Visibility
**Steps:**
1. Examine resize handle at bottom of chat
2. Hover over it
3. Check visual feedback

**Expected Result:**
- Handle clearly visible
- Hover effect changes background color
- Three-line indicator visible
- Cursor changes to resize cursor

**Status:** [ ] Pass [ ] Fail

---

### Test 22: Message Fade Animation
**Steps:**
1. Send multiple messages quickly
2. Observe animation quality

**Expected Result:**
- Smooth fade-in animation
- Subtle slide-up effect
- No flickering or jumps
- Professional appearance

**Status:** [ ] Pass [ ] Fail

---

## Integration Tests

### Test 23: Chat History Persistence
**Steps:**
1. Have conversation in Option 3
2. Include mix of summary-based and TShark-based queries
3. Refresh page
4. Load existing analysis

**Expected Result:**
- All previous messages restored
- Correct formatting maintained
- Both types of responses displayed properly

**Status:** [ ] Pass [ ] Fail

---

### Test 24: Multiple Session Test
**Steps:**
1. Upload and analyze PCAP #1 with Option 3
2. Set custom chat height
3. Delete analysis
4. Upload and analyze PCAP #2 with Option 3
5. Check chat height

**Expected Result:**
- Chat height persists across different analyses
- Each analysis has correct summary data
- No data leakage between analyses

**Status:** [ ] Pass [ ] Fail

---

## Summary

**Total Tests:** 24
**Passed:** ___
**Failed:** ___
**Pass Rate:** ___%

**Critical Issues Found:**
- [ ] None
- [ ] List any critical issues below

**Notes:**
[Add any additional observations or notes here]

---

## Sign-Off

**Tester Name:** _______________
**Date:** _______________
**Environment:** _______________
**Browser:** _______________
**Overall Assessment:** [ ] Approved [ ] Needs Fixes
