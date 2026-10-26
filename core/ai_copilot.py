import urllib.request
import urllib.parse
import json
import os
from .database import get_setting, get_stats, get_recent_logs

class InternetPoliceCopilot:
    """
    AI Copilot and Voice Commander for Internet Police.
    Powered by Free LLM APIs (Groq, Gemini, OpenRouter, Ollama, GitHub Models)
    with autonomous offline cybersecurity fallback.
    """
    def __init__(self):
        pass

    def call_groq(self, prompt, api_key, system_prompt):
        url = "https://api.groq.com/openai/v1/chat/completions"
        candidate_models = ["qwen/qwen3.8-27b", "openai/gpt-oss-120b", "openai/gpt-oss-20b", "llama-3.3-70b-versatile", "llama-3.1-8b-instant"]
        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) InternetPolice/1.0"
        }
        last_error = None
        for model in candidate_models:
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.5,
                "max_tokens": 1000
            }
            try:
                req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data["choices"][0]["message"]["content"]
            except Exception as e:
                last_error = e
                continue
        raise last_error if last_error else Exception("Groq model connection error")

    def call_gemini(self, prompt, api_key, system_prompt):
        api_key = api_key.strip()
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        combined_prompt = f"System Instructions: {system_prompt}\n\nUser Message:\n{prompt}"
        payload = {"contents": [{"parts": [{"text": combined_prompt}]}]}
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) InternetPolice/1.0"
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["candidates"][0]["content"]["parts"][0]["text"]

    def call_openrouter(self, prompt, api_key, system_prompt):
        url = "https://openrouter.ai/api/v1/chat/completions"
        payload = {
            "model": "deepseek/deepseek-r1:free",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        }
        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) InternetPolice/1.0"
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]

    def call_ollama(self, prompt, model="llama3"):
        url = "http://127.0.0.1:11434/api/generate"
        payload = {"model": model, "prompt": prompt, "stream": False}
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode()).get("response", "")

    def offline_police_agent(self, prompt):
        p_lower = prompt.lower()
        if "status" in p_lower or "report" in p_lower:
            stats = get_stats()
            return (
                f"🚨 **इंटरनेट पुलिस मुख्यालय स्थिति रिपोर्ट:**\n\n"
                f"• कुल सुरक्षित कनेक्शन: {stats['total_events']}\n"
                f"• ब्लॉक किए गए ट्रैकर्स: {stats['blocked_ads']}\n"
                f"• निष्प्रभावी मैलवेयर थ्रेट्स: {stats['blocked_threats']}\n"
                f"• डेटा रिसाव बचाव (DLP): {stats['dlp_alerts']}\n"
                f"• WAF फ़ायरवॉल ब्लॉक्स: {stats['waf_blocks']}\n\n"
                f"आपके सभी डिवाइसेस पर पुलिस पेट्रोल 24/7 सक्रिय है!"
            )
        elif "hack" in p_lower or "security" in p_lower:
            return (
                "🛡️ **इंटरनेट पुलिस साइबर रक्षा नियम:**\n\n"
                "1. **Never Trust, Always Verify**: हर इनकमिंग और आउटगोइंग पैकेट को WAF और DLP से गुजारा जाता है।\n"
                "2. **एन्क्रिप्टेड DNS**: Quad9 DoH द्वारा आपके ISP की निगरानी बंद की गई है।\n"
                "3. **पर्सनल डेटा कवच**: क्रेडिट कार्ड, पैन व आधार नंबर का अनधिकृत ट्रांसमिशन असंभव है।"
            )
        else:
            return (
                f"👮 **इंटरनेट पुलिस AI कमांडर:**\n\n"
                f"संदेश प्राप्त हुआ: '{prompt}'\n\n"
                "मैं आपके डिवाइस का मुख्य सुरक्षा गार्ड हूँ। आप मुझसे सुरक्षा विश्लेषण, संदिग्ध लिंक की जांच, "
                "या डिवाइस हार्डनिंग के बारे में कभी भी पूछ सकते हैं।"
            )

    def ask(self, user_prompt, provider=None, api_key=None):
        system_prompt = (
            "You are 'Internet Police' (इंटरनेट पुलिस), an elite Autonomous AI Cyber Commander guardian. "
            "Your duty is to protect user devices, laptops, and phones from hackers, scammers, ad tracking, and data theft. "
            "Speak with authoritative yet friendly tone, like an Indian cyber police officer / Jarvis. "
            "Respond naturally in Hindi/Hinglish/English depending on user choice. Keep advice practical, actionable, and secure."
        )

        if not provider:
            provider = get_setting("ai_provider", "groq")
        if not api_key:
            api_key = get_setting("ai_api_key", "").strip()

        # Safety Check: If user pasted a URL instead of an actual API key
        if api_key.startswith("http://") or api_key.startswith("https://"):
            return (
                "⚠️ **सूचना:** आपने API कुंजी की जगह GitHub का लिंक पेस्ट कर दिया है।\n\n"
                "इंटरनेट पुलिस वर्तमान में ऑफलाइन इंजन पर सुरक्षित काम कर रही है। कृपया सेटिंग्स में जाकर अपनी वास्तविक Groq API कुंजी (`gsk_...`) डालें।"
            )

        # If user has an active key in database
        try:
            if (provider == "groq" or api_key.startswith("gsk_")) and api_key:
                return self.call_groq(user_prompt, api_key, system_prompt)
            elif (provider == "gemini" or api_key.startswith("AIza")) and api_key:
                return self.call_gemini(user_prompt, api_key, system_prompt)
            elif (provider == "openrouter" or api_key.startswith("sk-or-")) and api_key:
                return self.call_openrouter(user_prompt, api_key, system_prompt)
            elif provider == "ollama":
                return self.call_ollama(user_prompt)
        except Exception as e:
            return f"⚠️ [Police Dispatch Cloud Notice: {str(e)[:50]}]\n\n{self.offline_police_agent(user_prompt)}"

        return self.offline_police_agent(user_prompt)
