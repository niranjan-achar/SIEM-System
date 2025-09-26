# app/nlp_query.py
"""
Simple rule-based NLP query handler for Avighna2.
Expands later with AI/LLM integration.
"""

import re

from app import ingest


def handle_query(text: str) -> str:
    """Parse a natural language query and return a response string."""
    t = text.lower().strip()

    # Find available log files
    import os

    log_files = []
    for log_file in ["logs/access.log", "logs/corrupt_access.log", "logs/test_web.log"]:
        if os.path.exists(log_file):
            log_files.append(log_file)

    if not log_files:
        return "No log files found. Please upload some logs first using the Log Ingestion feature."

    # Enhanced pattern matching with more flexible queries

    # Failed logins patterns
    failed_patterns = [
        r"show top (\d+) failed logins?",
        r"top (\d+) failed logins?",
        r"(\d+) failed logins?",
        r"failed logins? top (\d+)",
        r"show (\d+) failed",
        r"(\d+) failed",
    ]

    for pattern in failed_patterns:
        m = re.search(pattern, t)
        if m:
            n = int(m.group(1))
            try:
                # Try all available log files
                all_failed = []
                for log_file in log_files:
                    events = ingest.parse_access_log(log_file)
                    failed = [
                        e for e in events if e.get("code", 200) in (401, 403, 500)
                    ]
                    all_failed.extend(failed)

                if not all_failed:
                    return "No failed login attempts found in available logs."

                # Count by IP
                counts = {}
                for e in all_failed:
                    ip = e.get("ip", "unknown")
                    counts[ip] = counts.get(ip, 0) + 1

                top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]
                lines = [f"🚨 Top {n} Failed Login Sources:"]
                for ip, c in top:
                    lines.append(f"  • {ip}: {c} failed attempts")
                return "\n".join(lines)
            except Exception as e:
                return f"❌ Could not analyze failed logins: {e}"

    # Total events patterns
    total_patterns = [
        "total events",
        "how many events",
        "event count",
        "events total",
        "count events",
    ]
    if any(pattern in t for pattern in total_patterns):
        try:
            total_events = 0
            file_details = []
            for log_file in log_files:
                events = ingest.parse_access_log(log_file)
                total_events += len(events)
                file_details.append(
                    f"  • {os.path.basename(log_file)}: {len(events)} events"
                )

            response = [f"📊 Total Events Analysis:"]
            response.extend(file_details)
            response.append(f"\n🔢 Total across all files: {total_events} events")
            return "\n".join(response)
        except Exception as e:
            return f"❌ Could not count events: {e}"

    # Summary patterns
    summary_patterns = ["summary", "summarize", "overview", "analyze", "analysis"]
    if any(pattern in t for pattern in summary_patterns):
        try:
            # Generate comprehensive summary from all logs
            all_events = []
            file_summaries = []

            for log_file in log_files:
                events = ingest.parse_access_log(log_file)
                all_events.extend(events)
                summary = ingest.summarize_events(events)
                file_summaries.append(f"\n📁 {os.path.basename(log_file)}:\n{summary}")

            # Overall summary
            overall_summary = ingest.summarize_events(all_events)

            response = ["🔍 Comprehensive Security Analysis:"]
            response.append(f"\n📈 Overall Summary:\n{overall_summary}")
            response.extend(file_summaries)
            return "\n".join(response)
        except Exception as e:
            return f"❌ Could not generate summary: {e}"

    # Top IPs patterns
    ip_patterns = [
        r"top (\d+) ips?",
        r"show top (\d+) ips?",
        r"(\d+) top ips?",
        r"most active ips?",
    ]

    for pattern in ip_patterns:
        m = re.search(pattern, t)
        if m:
            n = int(m.group(1))
            try:
                all_events = []
                for log_file in log_files:
                    events = ingest.parse_access_log(log_file)
                    all_events.extend(events)

                ip_counts = {}
                for event in all_events:
                    ip = event.get("ip", "unknown")
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1

                top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[
                    :n
                ]
                lines = [f"🌐 Top {n} Most Active IPs:"]
                for ip, count in top_ips:
                    lines.append(f"  • {ip}: {count} requests")
                return "\n".join(lines)
            except Exception as e:
                return f"❌ Could not analyze top IPs: {e}"

    # Recent activity patterns
    if any(word in t for word in ["recent", "latest", "last", "new"]):
        try:
            # Get events from most recent log file
            recent_log = log_files[0]  # Assume first is most recent
            events = ingest.parse_access_log(recent_log)
            recent_events = events[-10:]  # Last 10 events

            lines = [f"⏰ Recent Activity from {os.path.basename(recent_log)}:"]
            for i, event in enumerate(recent_events, 1):
                ip = event.get("ip", "unknown")
                code = event.get("code", "unknown")
                req = event.get("req", "unknown request")
                lines.append(f"  {i}. {ip} - {code} - {req}")
            return "\n".join(lines)
        except Exception as e:
            return f"❌ Could not show recent activity: {e}"

    # Help/commands pattern
    if any(word in t for word in ["help", "commands", "what can", "how to"]):
        return """🤖 Avighna2 Natural Language Queries:

📊 Analytics:
  • "show top 5 failed logins"
  • "total events" or "how many events"
  • "summary" or "analyze logs"
  • "top 10 IPs" or "most active IPs"

⏰ Activity:
  • "recent activity" or "latest events" 
  • "show recent" or "what happened recently"

💡 Tips:
  • Be specific with numbers (e.g., "top 5", "last 10")
  • Use keywords like "failed", "summary", "recent"
  • Ask for "help" to see this message again

Try asking: "show top 3 failed logins" or "summarize logs"
"""

    # If no pattern matches, provide helpful response
    return f"""🤔 I didn't understand: "{text}"

Try asking questions like:
  • "show top 5 failed logins"
  • "how many total events"
  • "generate summary"
  • "top 10 IPs"
  • "recent activity"
  • "help" - for more options

💡 Tip: Be specific and use keywords like "top", "failed", "summary", or "recent"
"""
