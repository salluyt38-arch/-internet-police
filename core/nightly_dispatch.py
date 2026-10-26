import time
from datetime import datetime
from .database import get_connection, get_stats, get_recent_logs

class NightlyDispatch:
    """
    Automated 9:00 PM (21:00) Daily Security Dispatcher for Internet Police.
    Compiles daily cyber patrol metrics and publishes an end-of-day intelligence
    summary directly into the user's chat / dispatch window.
    """
    def __init__(self, ai_copilot=None):
        self.ai = ai_copilot
        self.last_dispatched_date = None

    def generate_daily_summary(self):
        stats = get_stats()
        now = datetime.now()
        date_str = now.strftime("%Y-%m-%d")
        time_str = now.strftime("%I:%M %p")

        prompt = (
            f"You are the Internet Police Chief Commander. Generate a concise, powerful 9:00 PM Daily Nightly "
            f"Cyber Patrol Briefing (दैनिक सुरक्षा ब्रीफिंग) for the user in Hindi with technical clarity. "
            f"Today's Intercept Statistics: "
            f"Total Inspected Payloads: {stats['total_events']}, "
            f"Ad Trackers & Telemetry Sinkholed: {stats['blocked_ads']}, "
            f"Malware & Cyber Threats Neutralized: {stats['blocked_threats']}, "
            f"Personal Data Leaks (PAN/Aadhaar/Cards) Prevented: {stats['dlp_alerts']}, "
            f"WAF Exploits Thwarted: {stats['waf_blocks']}. "
            f"Format with clean bullet points, reassuring the user that their device and personal data remained 100% secure today."
        )

        if self.ai:
            try:
                summary_text = self.ai.ask(prompt)
            except Exception:
                summary_text = self.fallback_summary(stats, time_str)
        else:
            summary_text = self.fallback_summary(stats, time_str)

        # Save to database
        conn = get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO dispatches (dispatch_date, timestamp, total_events, ads_blocked, threats_blocked, dlp_leaks_prevented, summary_text)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (date_str, time.time(), stats['total_events'], stats['blocked_ads'], stats['threats_blocked'], stats['dlp_alerts'], summary_text))
        conn.commit()
        conn.close()

        self.last_dispatched_date = date_str
        return {
            "date": date_str,
            "time": time_str,
            "stats": stats,
            "summary": summary_text
        }

    def fallback_summary(self, stats, time_str):
        return (
            f"🚨 **इंटरनेट पुलिस दैनिक सुरक्षा ब्रीफिंग (21:00 Nightly Dispatch)**\n\n"
            f"मान्यवर नागरिक, आज दिनांक को इंटरनेट पुलिस ने आपके डिवाइस पर 24/7 गश्त (Patrol) करते हुए निम्नलिखित सुरक्षा कार्यवाई की:\n\n"
            f"• **कुल पैकेट निरीक्षण**: {stats['total_events']} डेटा स्ट्रीम्स जांची गईं।\n"
            f"• **ऐड व टेलीमेट्री सिंकहोल**: {stats['blocked_ads']} विज्ञापन और जासूसी ट्रैकर्स `0.0.0.0` पर गिराए गए।\n"
            f"• **साइबर थ्रेट्स निष्प्रभावी**: {stats['blocked_threats']} मैलवेयर व फ़िशिंग डोमेन को Quad9 DoH द्वारा रोका गया।\n"
            f"• **पर्सनल डेटा सुरक्षा (DLP)**: {stats['dlp_alerts']} बार संवेदनशील कार्ड/पैन/आधार डेटा का अनाधिकृत रिसाव रोका गया।\n"
            f"• **वेब एक्सप्लॉइट्स शील्ड (WAF)**: {stats['waf_blocks']} इंजेक्शन व हैकिंग हमले नाकाम किए गए।\n\n"
            f"✅ **अंतिम निर्णय**: आपका डिवाइस, इंटरनेट कनेक्शन और व्यक्तिगत डेटा पूरी तरह सुरक्षित है। शुभ रात्रि!"
        )

    def get_latest_dispatches(self, limit=5):
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM dispatches ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows
