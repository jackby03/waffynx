import re

with open(".jules/sentinel.md", "r") as f:
    content = f.read()

# Replace the last entry format with the desired format
content = re.sub(r'Date: (2024-05-24)\nTitle: (Unsafe CORS OPTIONS Routing)\nVulnerability: (.*?)\nLearning: (.*?)\nPrevention: (.*)', r'## \1 - [\2]\n**Vulnerability:** \3\n**Learning:** \4\n**Prevention:** \5', content, flags=re.DOTALL)

with open(".jules/sentinel.md", "w") as f:
    f.write(content)
