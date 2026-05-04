import sys
sys.path.insert(0, ".")
from dotenv import load_dotenv
load_dotenv()
from providers.gemini import GeminiProvider

provider = GeminiProvider()

system = '''You are a test. Respond with this exact JSON:
{
  "verdict": "safe",
  "confidence": "high",
  "threat_types": [],
  "explanation": "test response",
  "key_indicators": []
}'''

result = provider.analyze(system, "Test email content here")
print(f"Success: {result.success}")
print(f"Verdict: {result.verdict}")
print(f"Confidence: {result.confidence}")
print(f"Explanation: {result.explanation}")
print(f"Error: {result.error}")
