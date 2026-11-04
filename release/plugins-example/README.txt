INTERLACE PLUGINS — Custom Active-Scan Rules
=============================================

Interlace loads extra active-scan checks from JSON files, so you can add your
own detections without rebuilding the program.

HOW TO USE
----------
1. Create a folder named  rules  inside your Interlace data directory
   (the -data folder; by default  interlace-data\rules ).
2. Drop one or more .json files there (e.g. custom-rules.json in this folder).
3. Restart Interlace. The console prints how many custom rules were loaded.
   Your checks now run on every "Scan" alongside the built-in ones.

RULE FORMAT
-----------
Each file is a JSON array of rule objects:

  {
    "id":       "unique-slug",          // identifier for the finding
    "name":     "Human Readable Name",  // finding title
    "severity": "high|medium|low|info",
    "type":     "grep|reflection|redirect|oob",
    "payloads": ["...", "..."],         // injected into each parameter
    "grep":     ["regex1", "regex2"],   // (grep type) case-insensitive regexes
    "detail":   "What this finding means."
  }

RULE TYPES
----------
  grep       Inject each payload, flag if any grep regex matches the response
             body but NOT the baseline (unmodified) response.
  reflection Inject a unique marker; flag if reflected unescaped in an HTML
             response (XSS). No payloads/grep needed.
  redirect   Inject an external URL; flag if it appears in a Location header.
  oob        Inject Interlace's out-of-band callback URL; flag if the target
             calls back (blind SSRF / external interaction). No payloads needed.

See custom-rules.json in this folder for working examples. Copy it into your
data directory's  rules  folder to try it.
