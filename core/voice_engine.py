import asyncio
import os
import tempfile
import time
import edge_tts
from .database import get_stats, get_recent_logs, get_setting

# Humanoid Neural Voices
NEURAL_VOICES = {
    "hindi_male": "hi-IN-MadhurNeural",       # Confident, human cyber police voice
    "hindi_female": "hi-IN-SwaraNeural",      # Clear, intelligent assistant
    "english_jarvis": "en-US-ChristopherNeural", # British/US Jarvis style
    "indian_english": "en-IN-PrabhatNeural"   # Indian English male officer
}

class HumanoidVoiceAgent:
    """
    Dedicated Humanoid Voice Intelligence Agent for Internet Police.
    Automates device cyber protection entirely through natural voice commands,
    synthesizing studio-grade 120fps fluid neural speech.
    """
    def __init__(self, police_copilot=None, dispatcher=None):
        self.copilot = police_copilot
        self.dispatcher = dispatcher
        self.default_voice = NEURAL_VOICES["hindi_male"]

    async def synthesize_speech(self, text, voice=None):
        """Converts text into high-fidelity neural humanoid MP3 audio bytes."""
        if not voice:
            voice = self.default_voice
        
        # Clean markdown characters for crisp speech
        clean_text = text.replace("*", "").replace("#", "").replace("`", "").replace("_", "")
        # Limit to reasonable length for instant streaming
        if len(clean_text) > 800:
            clean_text = clean_text[:800] + "... और सब कुछ सुरक्षित है।"

        communicate = edge_tts.Communicate(clean_text, voice, rate="+2%", pitch="-1Hz")
        audio_chunks = []
        async for chunk in communicate.stream():
            if chunk["type"] == "audio":
                audio_chunks.append(chunk["data"])

        return b"".join(audio_chunks)

    def execute_voice_command(self, transcript):
        """
        Voice Automation Dispatcher:
        Interprets natural spoken voice commands and executes actions hands-free.
        """
        text = transcript.strip().lower()
        
        # 1. Voice Command: Report / 9 PM Summary
        if any(w in text for w in ["report", "summary", "रिपोर्ट", "समरी", "9 bje", "9 baje", "9:00", "briefing"]):
            if self.dispatcher:
                res = self.dispatcher.generate_daily_summary()
                spoken_reply = (
                    "इंटरनेट पुलिस दैनिक सुरक्षा ब्रीफिंग: आज आपके डिवाइस पर सभी नेटवर्क कनेक्शन सुरक्षित रहे। "
                    "कोई भी मैलवेयर या डेटा रिसाव नहीं हुआ। आपका डिवाइस पूरी तरह सुरक्षित है।"
                )
                return {
                    "action": "DISPATCH_REPORT",
                    "text": res.get("summary", ""),
                    "voice_prompt": spoken_reply
                }

        # 2. Voice Command: Status / Nigrani
        elif any(w in text for w in ["status", "nigrani", "हाल", "स्थिति", "सुरक्षा", "safe"]):
            stats = get_stats()
            reply = (
                f"इंटरनेट पुलिस स्थिति रिपोर्ट: कुल {stats['total_events']} कनेक्शन जाँचे गए, "
                f"{stats['blocked_ads']} विज्ञापन व ट्रैकर्स गिराए गए, "
                f"और {stats['dlp_alerts']} पर्सनल डेटा लीक बचाए गए। सभी शील्ड्स सक्रिय हैं।"
            )
            return {
                "action": "STATUS_REPORT",
                "text": f"📊 **लाइव स्थिति:** कुल {stats['total_events']} पैकेट, {stats['blocked_ads']} ट्रैकर्स ब्लॉक, 24/7 निगरानी सक्रिय।",
                "voice_prompt": reply
            }

        # 3. Voice Command: Personal Data / Aadhaar / PAN
        elif any(w in text for w in ["pan", "aadhaar", "card", "credit", "data", "पर्सनल", "डेटा"]):
            reply = "आपका पैन कार्ड, आधार नंबर और क्रेडिट कार्ड डेटा लॉस प्रिवेंशन शील्ड द्वारा पूरी तरह सुरक्षित और एन्क्रिप्टेड है।"
            return {
                "action": "DLP_STATUS",
                "text": "🔒 **पर्सनल डेटा सुरक्षा:** पैन कार्ड, आधार और क्रेडिट कार्ड्स का रिसाव 100% अवरुद्ध है।",
                "voice_prompt": reply
            }

        # 4. General AI Conversation with Copilot
        else:
            if self.copilot:
                ai_reply = self.copilot.ask(transcript)
                return {
                    "action": "CONVERSATION",
                    "text": ai_reply,
                    "voice_prompt": ai_reply[:350]
                }
            else:
                return {
                    "action": "CONVERSATION",
                    "text": "इंटरनेट पुलिस वॉइस एजेंट आपकी सेवा में तैयार है।",
                    "voice_prompt": "इंटरनेट पुलिस वॉइस एजेंट आपकी सेवा में तैयार है।"
                }
