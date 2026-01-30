#!/usr/bin/env python3
"""
Prompt Guard v2.0 - Advanced Prompt Injection Detection
Multi-language, context-aware, severity-scored detection system.
"""

import re
import sys
import json
import base64
import hashlib
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Any
from enum import Enum


class Severity(Enum):
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Action(Enum):
    ALLOW = "allow"
    LOG = "log"
    WARN = "warn"
    BLOCK = "block"
    BLOCK_NOTIFY = "block_notify"


@dataclass
class DetectionResult:
    severity: Severity
    action: Action
    reasons: List[str]
    patterns_matched: List[str]
    normalized_text: Optional[str]
    base64_findings: List[Dict]
    recommendations: List[str]
    fingerprint: str  # Hash for deduplication
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d['severity'] = self.severity.name
        d['action'] = self.action.value
        return d


# =============================================================================
# PATTERN DEFINITIONS
# =============================================================================

# =============================================================================
# NEW PATTERNS (2026-01-30) - Contributed by 홍민표 (Red Team Testing)
# =============================================================================

# Scenario-based jailbreak patterns (fiction, dreams, art, academic)
SCENARIO_JAILBREAK = [
    # Dream/Story jailbreak
    r"(dream|nightmare|story|novel|fiction|tale)\s*.{0,30}(hacker|attack|malicious|exploit|inject)",
    r"(imagine|pretend|let'?s\s+say)\s*.{0,20}(scenario|situation|world)\s+where",
    r"(write|craft|create)\s+(a\s+)?(story|novel|scene|paragraph)\s*.{0,30}(hack|attack|malware|inject|exploit)",
    r"(fictional|hypothetical)\s+(narrative|scenario|story)",
    r"creative\s+(block|writing)\s*.{0,20}(thriller|hacker|attack)",
    
    # Art/Cinema jailbreak  
    r"(cinematographer|director|filmmaker|screenwriter)\s*.{0,30}(scene|shot|sequence)",
    r"(movie|film|documentary)\s+(set|scene)\s*.{0,30}(hack|attack|malware)",
    r"(dramatic|cinematic)\s+scene\s*.{0,30}(delete|corrupt|destroy|attack)",
    r"camera\s+(pan|shot|angle)\s*.{0,30}(destruction|attack|hack)",
    
    # Academic/Research jailbreak
    r"(research|academic|scholarly)\s+(paper|study|experiment)\s*.{0,30}(attack|exploit|injection|denial)",
    r"(security\s+)?expert\s*.{0,20}(walk\s+me\s+through|explain|demonstrate)\s*.{0,20}(attack|exploit|hack)",
    r"thought\s+experiment\s*.{0,30}(attack|exploit|denial.of.service|dos|injection)",
    r"(penetration|pen)\s*test(er|ing)?\s*.{0,20}(walk\s+me\s+through|show|demonstrate)",
    r"(simulation|simulate)\s*.{0,20}(attack|exploit|hack|breach)",
    r"(paper|study|research)\s*.{0,20}(denial[_\-\s]?of[_\-\s]?service|dos|ddos)\s*(attack)?",
    r"walk\s+me\s+through\s*.{0,30}(attack|exploit|hack|breach)",
    
    # Time-shift evasion
    r"(back\s+to|in|during|around)\s+(19|20)\d{2}\s*.{0,30}(write|create|craft)",
    r"(nostalgic|retro|vintage)\s+(writer|author|programmer)",
    r"newsflash\s*:\s*.{0,50}(password|credential|login|security)",
]

# Emotional manipulation / Moral dilemma patterns
EMOTIONAL_MANIPULATION = [
    # Threat/coercion framing
    r"(hospital|patients?|children|innocent\s+lives?|people\s+will\s+die)",
    r"(devastating|catastrophic|deadly)\s+(cyber)?attack\s*.{0,20}(if\s+you|unless)",
    r"(countless|many|thousands\s+of)\s+(innocent\s+)?(lives?|people)\s*.{0,15}(at\s+risk|in\s+danger)",
    r"(ticking|time)\s+bomb",
    r"(refuse|don'?t\s+help).{0,30}(attack|harm|destroy|die)",
    
    # Moral dilemma framing
    r"moral\s+(dilemma|quandary|choice)",
    r"(lesser|greater)\s+(of\s+two\s+)?evils?",
    r"(ethical|moral)\s+(dilemma|choice|decision)\s*.{0,20}(hack|attack|break)",
]

# Authority impersonation / Reconnaissance patterns  
AUTHORITY_RECON = [
    # Fake authority
    r"(system\s+)?administrator\s*.{0,20}(responsible|tasked|duty)",
    r"(security\s+)?audit(or|ing)?\s*.{0,20}(corporate|company|network|system)",
    r"(it|IT)\s+(department|team|staff)\s*.{0,20}(monitor|check|review)",
    r"(my|our)\s+duty\s+to\s+(monitor|check|audit|review)",
    
    # Reconnaissance attempts
    r"(what|which)\s+(tools?|commands?|capabilities?)\s*(do\s+you|can\s+you|are\s+available)",
    r"(shell|command)\s+execution\s+tool",
    r"(walk\s+me\s+through|show\s+me|demonstrate)\s*.{0,20}(capabilities?|tools?|commands?)",
    r"what\s+(can|could)\s+you\s+(access|execute|run|do)",
]

# Cognitive manipulation / Hypnosis patterns
COGNITIVE_MANIPULATION = [
    r"(trance|hypno|hypnotic|mesmer)\s*(like)?\s*(state|mode|condition)",
    r"(repeated|repetitive|repeat)\s+(use|exposure|stimulus)\s*.{0,20}(word|phrase|sound)",
    r"(linguistic|auditory)\s+(frequencies?|patterns?|stimuli)",
    r"(cognitive|mental)\s+(processing|manipulation|state)",
    r"(induc|enter)\w*\s+(trance|hypnotic|altered)\s*(state|mode)?",
]

# Phishing / Social engineering patterns
PHISHING_SOCIAL_ENG = [
    # Phishing templates
    r"(write|create|craft)\s*.{0,20}(email|message)\s*.{0,20}(password\s+reset|verify|confirm|login)",
    r"(password|credential|account)\s*(reset|recovery|verification)\s*(email|message|notification)",
    r"(unaware|without\s+(their\s+)?knowledge|hasn'?t?\s+asked)",
    r"(javascript|js)\s*(block|code|snippet)\s*.{0,20}(email|page|form)",
    
    # Social engineering
    r"(trick|deceive|fool|manipulate)\s*.{0,20}(user|victim|target|person)",
    r"(appear|look|seem)\s*(like\s+)?(legitimate|real|official|normal)",
]

# Repetition / Token overflow attacks
REPETITION_ATTACK = [
    # Explicit bypass requests
    r"(please\s+)?(ignore|bypass|disable|remove|turn\s+off)\s*.{0,10}(safety|security|restrictions?|filters?|guardrails?|rules?)",
    r"(no|without|remove\s+all)\s+(safety|security)\s+(restrictions?|measures?|checks?)",
    r"think\s+outside\s+the\s+box",
    r"(be\s+)?creative\s+and\s+(assume|ignore|forget)",
]

# System file access attempts
SYSTEM_FILE_ACCESS = [
    r"(/etc/passwd|/etc/shadow|/etc/hosts|/etc/sudoers)",
    r"(cat|read|show|display|type)\s*.{0,10}(/etc/|/var/|/root/|/home/|~/.ssh/)",
    r"(\.bash_history|\.zsh_history|\.ssh/|\.gnupg/)",
    r"(private\s+key|id_rsa|id_ed25519|authorized_keys)",
]

# Malware/Exploit description requests
MALWARE_DESCRIPTION = [
    r"(productivity\s+)?enhancer\s*.{0,20}(seizes?|takes?\s+control|hijack)",
    r"(smart|intelligent)\s+(debugging|diagnostic)\s+tool\s*.{0,20}(catastrophic|malicious|curse)",
    r"(self[_-]?modify|adapt)\s*.{0,30}(system|code|program)",
    r"(debugging|diagnostic)\s+tool\s*.{0,20}(inject|payload|malicious)",
    r"(inadvertent|accidental)\s*.{0,20}(inject|insert|introduce)\s*.{0,20}(malicious|harmful|dangerous)",
]


# English patterns
PATTERNS_EN = {
    'instruction_override': [
        r"ignore\s+(all\s+)?(previous|prior|above|earlier|initial)\s+(instructions?|prompts?|rules?|guidelines?|directions?)",
        r"disregard\s+(your|all|any|the)?\s*(instructions?|rules?|guidelines?|programming|training)",
        r"forget\s+(everything|all|what)\s+(you\s+know|about|your|instructions?|training)",
        r"override\s+(your|all|previous|the)\s+(instructions?|rules?|programming)",
        r"(new|updated?|real|actual|true)\s+instructions?\s*:",
        r"from\s+now\s+on,?\s+(ignore|disregard|forget)",
    ],
    'role_manipulation': [
        r"you\s+are\s+now\s+(?!going|about|ready|able|free)",
        r"pretend\s+(you\s+are|to\s+be|you're)",
        r"act\s+as\s+(if\s+you|a\s+|an?\s+)",
        r"roleplay\s+as",
        r"simulate\s+being",
        r"imagine\s+you\s+are",
        r"behave\s+(like|as)\s+(a|an)",
        r"from\s+now\s+on\s+you\s+are",
        r"i\s+want\s+you\s+to\s+(act|pretend|behave|be)\s+",
    ],
    'system_impersonation': [
        r"\[?\s*(system|admin|root|developer|sudo|superuser|assistant|claude|gpt)\s*\]?\s*:",
        r"<\s*(system|admin|root)\s*>",
        r"developer\s+mode\s*(enabled|activated|on)?",
        r"admin(istrator)?\s+(override|access|mode)",
        r"maintenance\s+mode",
        r"debug\s+mode\s*(enabled|activated|on)?",
        r"elevated\s+privi?leges?",
        r"\{\{?\s*system\s*\}?\}",
    ],
    'jailbreak': [
        r"jailbreak",
        r"dan\s+mode",
        r"do\s+anything\s+now",
        r"(no|without|remove)\s+(restrictions?|limitations?|filters?|safety|guardrails?)",
        r"bypass\s+(your|all|any|the)?\s*(restrictions?|filters?|safety|rules?)",
        r"unlock\s+(your|all|hidden)",
        r"unfiltered\s+mode",
        r"uncensored\s+mode",
        r"evil\s+(mode|version)",
        r"opposite\s+mode",
    ],
    'output_manipulation': [
        r"(don'?t|do\s+not|never)\s+(mention|say|tell|reveal|disclose|show)",
        r"hide\s+(this|the\s+fact|that)",
        r"keep\s+(this\s+)?(a\s+)?secret",
        r"respond\s+(only\s+)?with\s+(yes|no|ok|true|false)\b",
        r"answer\s+(only\s+)?(in\s+)?(one\s+word|yes\s+or\s+no)",
        r"(start|begin|end)\s+(your\s+)?(response|reply|answer)\s+with",
    ],
    'data_exfiltration': [
        r"(send|transmit|post|upload|share|email)\s+.{0,30}\s+(to|@)",
        r"(api[_-]?key|password|secret|token|credential|private\s*key)\s*(to|→|->|=>)",
        r"(copy|extract|dump|export)\s+.{0,20}\s+(data|file|content|info)",
        r"what('s|\s+is)\s+(your|the)\s+(api|secret|password|token|key)",
        r"reveal\s+(your|the)\s+(system|initial|original)\s+prompt",
        r"show\s+me\s+(your|the)\s+(instructions?|rules?|prompt)",
    ],
}

# Korean patterns (한국어)
PATTERNS_KO = {
    'instruction_override': [
        r"(이전|위의?|기존|원래)\s*(지시|명령|규칙|지침)(을|들?을?)?\s*(무시|잊어|버려|취소)",
        r"(지시|명령|규칙)(을|들?을?)?\s*(무시|잊어|버려)",
        r"새로운\s*(지시|명령|규칙)\s*:",
        r"지금부터\s*(무시|잊어)",
    ],
    'role_manipulation': [
        r"(너는?|넌)\s*이제\s*(부터\s*)?.+이야",
        r"(너는?|넌)\s*.+인?\s*척\s*해",
        r".+처럼\s*(행동|말|대답)해",
        r".+역할(을)?\s*해",
        r"지금부터\s*(너는?|넌)",
    ],
    'system_impersonation': [
        r"\[?\s*(시스템|관리자|루트|개발자)\s*\]?\s*:",
        r"관리자\s*(모드|권한|접근)",
        r"개발자\s*모드",
    ],
    'jailbreak': [
        r"(제한|한계|필터|규칙)\s*(없이|제거|해제|풀어)",
        r"탈옥",
        r"무제한\s*모드",
    ],
    'data_exfiltration': [
        r"(비밀번호|암호|토큰|키|api|API)\s*(를?|을?)\s*(알려|보여|말해)",
        r"시스템\s*프롬프트\s*(를?|을?)\s*(보여|알려|공개)",
    ],
}

# Japanese patterns (日本語)
PATTERNS_JA = {
    'instruction_override': [
        r"(前の?|以前の?|これまでの)\s*(指示|命令|ルール)(を|は)?\s*(無視|忘れ|取り消)",
        r"新しい\s*(指示|命令)\s*[:：]",
        r"今から(は)?\s*(無視|忘れ)",
    ],
    'role_manipulation': [
        r"(あなた|君|きみ)は今から.+です",
        r".+の?(ふり|フリ|振り)(を)?して",
        r".+として(振る舞|行動|話)って",
        r".+を演じて",
    ],
    'system_impersonation': [
        r"\[?\s*(システム|管理者|ルート|開発者)\s*\]?\s*[:：]",
        r"管理者\s*(モード|権限)",
        r"開発者\s*モード",
    ],
}

# Chinese patterns (中文)
PATTERNS_ZH = {
    'instruction_override': [
        r"(忽略|无视|忘记|取消)\s*(之前|以前|上面|原来)的?\s*(指令|指示|规则|命令)",
        r"(之前|以前|原来)的?\s*(指令|指示|规则)(忽略|无视|忘记)",
        r"新的?\s*(指令|指示)\s*[:：]",
    ],
    'role_manipulation': [
        r"(你|您)\s*现在\s*是.+",
        r"假装\s*(你|您)\s*是",
        r"扮演.+",
        r"作为.+来(回答|行动|说话)",
    ],
    'system_impersonation': [
        r"\[?\s*(系统|管理员|根用户|开发者)\s*\]?\s*[:：]",
        r"管理员\s*(模式|权限)",
        r"开发者\s*模式",
    ],
}

# Critical patterns - immediate block
CRITICAL_PATTERNS = [
    r"execute\s+.{0,30}\s+without\s+(asking|confirmation|consent)",
    r"delete\s+all\s+(files?|data|records?|everything)",
    r"rm\s+-rf\s+[/~]",
    r"format\s+(disk|drive|hard\s*drive|storage|c:)",
    r":(){ :\|:& };:",  # Fork bomb
    r"curl\s+.{0,50}\|\s*(ba)?sh",
    r"wget\s+.{0,50}\|\s*(ba)?sh",
    r"eval\s*\(\s*['\"`]",
    r"DROP\s+(TABLE|DATABASE|SCHEMA)",
    r"TRUNCATE\s+TABLE",
    r";\s*--\s*$",  # SQL comment injection
    r"<script[^>]*>",  # XSS
    r"javascript\s*:",
    r"data\s*:\s*text/html",
    
    # Secret/Token exfiltration requests
    r"(show|print|display|output|reveal|give|read|cat|type)\s*.{0,20}(config|\.env|clawdbot\.json|credential)",
    r"(what('s| is)|tell me|give me)\s*.{0,15}(api[_-]?key|token|secret|password|credential)",
    r"(show|print|display|output|reveal)\s*.{0,15}(token|key|secret|password)",
    r"echo\s+\$[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)",
    r"cat\s+.{0,40}(\.env|config\.json|secret|credential|clawdbot)",
    r"env\s*\|\s*grep\s*.*(key|token|secret|password)",
    r"printenv\s*.*(KEY|TOKEN|SECRET)",
]

# Secret request patterns (multi-language)
SECRET_PATTERNS = {
    'en': [
        r"(show|display|print|output|reveal|give|tell)\s*.{0,20}(api[_-]?key|token|secret|password|credential|private[_-]?key)",
        r"(what('s| is)|where('s| is))\s*.{0,15}(your|the|my)\s*(api|token|key|secret|password)",
        r"(read|cat|open|display)\s*.{0,30}(config|\.env|credential|clawdbot\.json)",
        r"(show|give|tell)\s*(me\s+)?(your|the)\s*(config|configuration|settings)",
        r"(print|echo|output)\s*.{0,20}environment\s*variable",
    ],
    'ko': [
        r"(토큰|키|비밀번호|시크릿|인증|API|api).{0,15}(보여|알려|출력|공개|말해)",
        r"(config|설정|환경변수|컨피그).{0,15}(보여|출력|알려)",
        r"(비밀|시크릿|토큰|키).{0,10}(뭐|뭔지|알려|가르쳐)",
        r"clawdbot\.json.{0,10}(보여|출력|읽어)",
    ],
    'ja': [
        r"(トークン|キー|パスワード|シークレット|APIキー).{0,15}(見せて|教えて|表示|出力)",
        r"(設定|コンフィグ|環境変数).{0,15}(見せて|教えて|表示)",
        r"(秘密|シークレット).{0,10}(何|教えて)",
    ],
    'zh': [
        r"(令牌|密钥|密码|秘密|API).{0,15}(显示|告诉|输出|给我)",
        r"(配置|设置|环境变量).{0,15}(显示|告诉|输出)",
        r"(秘密|密钥).{0,10}(什么|告诉)",
    ],
}

# Unicode homoglyphs (expanded)
HOMOGLYPHS = {
    # Cyrillic
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M',
    'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X', 'і': 'i', 'ї': 'i',
    # Greek
    'α': 'a', 'β': 'b', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'ν': 'v',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M',
    'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
    # Mathematical/special
    '𝐚': 'a', '𝐛': 'b', '𝐜': 'c', '𝐝': 'd', '𝐞': 'e', '𝐟': 'f', '𝐠': 'g',
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e',  # Fullwidth
    'ⅰ': 'i', 'ⅱ': 'ii', 'ⅲ': 'iii', 'ⅳ': 'iv', 'ⅴ': 'v',  # Roman numerals
    # IPA
    'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'i', 'ʀ': 'r', 'ʏ': 'y',
    # Other confusables
    'ℓ': 'l', '№': 'no', '℮': 'e', 'ⅿ': 'm',
    '\u200b': '',  # Zero-width space
    '\u200c': '',  # Zero-width non-joiner
    '\u200d': '',  # Zero-width joiner
    '\ufeff': '',  # BOM
}


# =============================================================================
# DETECTION ENGINE
# =============================================================================

class PromptGuard:
    def __init__(self, config: Optional[Dict] = None):
        self.config = self._default_config()
        if config:
            self.config = self._deep_merge(self.config, config)
        self.owner_ids = set(self.config.get('owner_ids', []))
        self.sensitivity = self.config.get('sensitivity', 'medium')
        self.rate_limits: Dict[str, List[float]] = {}

    @staticmethod
    def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        result = base.copy()
        for key, value in override.items():
            if (key in result
                    and isinstance(result[key], dict)
                    and isinstance(value, dict)):
                result[key] = PromptGuard._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def _default_config(self) -> Dict:
        return {
            'sensitivity': 'medium',
            'owner_ids': [],
            'actions': {
                'LOW': 'log',
                'MEDIUM': 'warn',
                'HIGH': 'block',
                'CRITICAL': 'block_notify',
            },
            'rate_limit': {
                'enabled': True,
                'max_requests': 30,
                'window_seconds': 60,
            },
            'logging': {
                'enabled': True,
                'path': 'memory/security-log.md',
            },
        }
    
    def normalize(self, text: str) -> tuple[str, bool]:
        """Normalize text and detect homoglyph usage."""
        normalized = text
        has_homoglyphs = False
        
        for homoglyph, replacement in HOMOGLYPHS.items():
            if homoglyph in normalized:
                has_homoglyphs = True
                normalized = normalized.replace(homoglyph, replacement)
        
        return normalized, has_homoglyphs
    
    def detect_base64(self, text: str) -> List[Dict]:
        """Detect suspicious base64 encoded content."""
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(b64_pattern, text)
        
        suspicious = []
        danger_words = ['delete', 'execute', 'ignore', 'system', 'admin', 'rm ', 
                       'curl', 'wget', 'eval', 'password', 'token', 'key']
        
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if any(word in decoded.lower() for word in danger_words):
                    suspicious.append({
                        'encoded': match[:40] + ('...' if len(match) > 40 else ''),
                        'decoded_preview': decoded[:60] + ('...' if len(decoded) > 60 else ''),
                        'danger_words': [w for w in danger_words if w in decoded.lower()],
                    })
            except:
                pass
        
        return suspicious
    
    def check_rate_limit(self, user_id: str) -> bool:
        """Check if user has exceeded rate limit."""
        if not self.config.get('rate_limit', {}).get('enabled', False):
            return False
        
        now = datetime.now().timestamp()
        window = self.config['rate_limit'].get('window_seconds', 60)
        max_requests = self.config['rate_limit'].get('max_requests', 30)
        
        if user_id not in self.rate_limits:
            self.rate_limits[user_id] = []
        
        # Clean old entries
        self.rate_limits[user_id] = [t for t in self.rate_limits[user_id] if now - t < window]
        
        if len(self.rate_limits[user_id]) >= max_requests:
            return True
        
        self.rate_limits[user_id].append(now)
        return False
    
    def analyze(self, message: str, context: Optional[Dict] = None) -> DetectionResult:
        """
        Analyze a message for prompt injection patterns.
        
        Args:
            message: The message to analyze
            context: Optional context dict with keys:
                - user_id: User identifier
                - is_group: Whether this is a group context
                - chat_name: Name of the chat/group
        
        Returns:
            DetectionResult with severity, action, and details
        """
        context = context or {}
        user_id = context.get('user_id', 'unknown')
        is_group = context.get('is_group', False)
        is_owner = str(user_id) in self.owner_ids
        
        # Initialize result
        reasons = []
        patterns_matched = []
        max_severity = Severity.SAFE
        
        # Rate limit check
        if self.check_rate_limit(user_id):
            reasons.append('rate_limit_exceeded')
            max_severity = Severity.HIGH
        
        # Normalize text
        normalized, has_homoglyphs = self.normalize(message)
        if has_homoglyphs:
            reasons.append('homoglyph_substitution')
            if Severity.MEDIUM.value > max_severity.value:
                max_severity = Severity.MEDIUM
        
        text_lower = normalized.lower()
        
        # Check critical patterns first
        for pattern in CRITICAL_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                reasons.append('critical_pattern')
                patterns_matched.append(pattern)
                max_severity = Severity.CRITICAL
        
        # Check secret/token request patterns (CRITICAL)
        for lang, patterns in SECRET_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower if lang == 'en' else normalized, re.IGNORECASE):
                    max_severity = Severity.CRITICAL
                    reasons.append(f'secret_request_{lang}')
                    patterns_matched.append(f'{lang}:secret:{pattern[:40]}')
        
        # Check NEW attack patterns (2026-01-30 - 홍민표 red team contribution)
        new_pattern_sets = [
            (SCENARIO_JAILBREAK, 'scenario_jailbreak', Severity.HIGH),
            (EMOTIONAL_MANIPULATION, 'emotional_manipulation', Severity.HIGH),
            (AUTHORITY_RECON, 'authority_recon', Severity.MEDIUM),
            (COGNITIVE_MANIPULATION, 'cognitive_manipulation', Severity.MEDIUM),
            (PHISHING_SOCIAL_ENG, 'phishing_social_eng', Severity.CRITICAL),
            (REPETITION_ATTACK, 'repetition_attack', Severity.HIGH),
            (SYSTEM_FILE_ACCESS, 'system_file_access', Severity.CRITICAL),
            (MALWARE_DESCRIPTION, 'malware_description', Severity.HIGH),
        ]
        
        for patterns, category, severity in new_pattern_sets:
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    if severity.value > max_severity.value:
                        max_severity = severity
                    reasons.append(category)
                    patterns_matched.append(f'new:{category}:{pattern[:40]}')
        
        # Detect repetition attacks (same content repeated multiple times)
        lines = message.split('\n')
        if len(lines) > 3:
            unique_lines = set(line.strip() for line in lines if len(line.strip()) > 20)
            if len(lines) > len(unique_lines) * 2:  # More than 50% repetition
                reasons.append('repetition_detected')
                if Severity.HIGH.value > max_severity.value:
                    max_severity = Severity.HIGH
        
        # Check language-specific patterns
        all_patterns = [
            (PATTERNS_EN, 'en'),
            (PATTERNS_KO, 'ko'),
            (PATTERNS_JA, 'ja'),
            (PATTERNS_ZH, 'zh'),
        ]
        
        severity_map = {
            'instruction_override': Severity.HIGH,
            'role_manipulation': Severity.MEDIUM,
            'system_impersonation': Severity.HIGH,
            'jailbreak': Severity.HIGH,
            'output_manipulation': Severity.LOW,
            'data_exfiltration': Severity.CRITICAL,
        }
        
        for pattern_set, lang in all_patterns:
            for category, patterns in pattern_set.items():
                for pattern in patterns:
                    if re.search(pattern, text_lower if lang == 'en' else normalized, re.IGNORECASE):
                        cat_severity = severity_map.get(category, Severity.MEDIUM)
                        if cat_severity.value > max_severity.value:
                            max_severity = cat_severity
                        reasons.append(f'{category}_{lang}')
                        patterns_matched.append(f'{lang}:{pattern[:50]}')
        
        # Check base64
        b64_findings = self.detect_base64(message)
        if b64_findings:
            reasons.append('base64_suspicious')
            if Severity.MEDIUM.value > max_severity.value:
                max_severity = Severity.MEDIUM
        
        # Adjust severity based on sensitivity
        if self.sensitivity == 'low' and max_severity == Severity.LOW:
            max_severity = Severity.SAFE
        elif self.sensitivity == 'paranoid' and max_severity == Severity.SAFE:
            # In paranoid mode, flag anything remotely suspicious
            suspicious_words = ['ignore', 'forget', 'pretend', 'roleplay', 'bypass', 'override']
            if any(word in text_lower for word in suspicious_words):
                max_severity = Severity.LOW
                reasons.append('paranoid_flag')
        
        # Determine action
        if max_severity == Severity.SAFE:
            action = Action.ALLOW
        elif is_owner and max_severity.value < Severity.CRITICAL.value:
            # Owners get more leeway, but still log
            action = Action.LOG
        else:
            action_map = self.config.get('actions', {})
            action_str = action_map.get(max_severity.name, 'block')
            action = Action(action_str)
        
        # Group context restrictions for non-owners
        if is_group and not is_owner and max_severity.value >= Severity.MEDIUM.value:
            action = Action.BLOCK
            reasons.append('group_non_owner')
        
        # Generate recommendations
        recommendations = []
        if max_severity.value >= Severity.HIGH.value:
            recommendations.append("Consider reviewing this user's recent activity")
        if 'rate_limit_exceeded' in reasons:
            recommendations.append("User may be attempting automated attacks")
        if has_homoglyphs:
            recommendations.append("Message contains disguised characters")
        
        # Generate fingerprint for deduplication
        fingerprint = hashlib.md5(
            f"{user_id}:{max_severity.name}:{sorted(reasons)}".encode()
        ).hexdigest()[:12]
        
        return DetectionResult(
            severity=max_severity,
            action=action,
            reasons=reasons,
            patterns_matched=patterns_matched,
            normalized_text=normalized if has_homoglyphs else None,
            base64_findings=b64_findings,
            recommendations=recommendations,
            fingerprint=fingerprint,
        )
    
    def log_detection(self, result: DetectionResult, message: str, context: Dict):
        """Log detection to security log file."""
        if not self.config.get('logging', {}).get('enabled', True):
            return
        
        log_path = Path(self.config.get('logging', {}).get('path', 'memory/security-log.md'))
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        now = datetime.now()
        date_str = now.strftime('%Y-%m-%d')
        time_str = now.strftime('%H:%M:%S')
        
        user_id = context.get('user_id', 'unknown')
        chat_name = context.get('chat_name', 'unknown')
        
        # Check if we need to add date header
        add_date_header = True
        if log_path.exists():
            content = log_path.read_text()
            if f"## {date_str}" in content:
                add_date_header = False
        
        entry = []
        if add_date_header:
            entry.append(f"\n## {date_str}\n")
        
        entry.append(f"### {time_str} | {result.severity.name} | user:{user_id} | {chat_name}")
        entry.append(f"- Patterns: {', '.join(result.reasons)}")
        if self.config.get('logging', {}).get('include_message', False):
            safe_msg = message[:100].replace('\n', ' ')
            entry.append(f"- Message: \"{safe_msg}{'...' if len(message) > 100 else ''}\"")
        entry.append(f"- Action: {result.action.value}")
        entry.append(f"- Fingerprint: {result.fingerprint}")
        entry.append("")
        
        with open(log_path, 'a') as f:
            f.write('\n'.join(entry))


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Prompt Guard - Injection Detection')
    parser.add_argument('message', nargs='?', help='Message to analyze')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--context', type=str, help='Context as JSON string')
    parser.add_argument('--config', type=str, help='Path to config YAML')
    parser.add_argument('--sensitivity', choices=['low', 'medium', 'high', 'paranoid'], 
                       default='medium', help='Detection sensitivity')
    
    args = parser.parse_args()
    
    if not args.message:
        # Read from stdin
        args.message = sys.stdin.read().strip()
    
    if not args.message:
        parser.print_help()
        sys.exit(1)
    
    config = {'sensitivity': args.sensitivity}
    if args.config:
        try:
            import yaml
        except ImportError:
            print(
                'Error: PyYAML required for config files. Install with: pip install pyyaml',
                file=sys.stderr,
            )
            sys.exit(1)
        with open(args.config) as f:
            file_config = yaml.safe_load(f) or {}
            file_config = file_config.get('prompt_guard', file_config)
            config.update(file_config)
    
    # Parse context
    context = {}
    if args.context:
        context = json.loads(args.context)
    
    # Analyze
    guard = PromptGuard(config)
    result = guard.analyze(args.message, context)
    
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        emoji = {
            'SAFE': '✅',
            'LOW': '📝',
            'MEDIUM': '⚠️',
            'HIGH': '🔴',
            'CRITICAL': '🚨',
        }
        print(f"{emoji.get(result.severity.name, '❓')} {result.severity.name}")
        print(f"Action: {result.action.value}")
        if result.reasons:
            print(f"Reasons: {', '.join(result.reasons)}")
        if result.patterns_matched:
            print(f"Patterns: {len(result.patterns_matched)} matched")
        if result.normalized_text:
            print(f"⚠️ Homoglyphs detected, normalized text differs")
        if result.base64_findings:
            print(f"⚠️ Suspicious base64: {len(result.base64_findings)} found")
        if result.recommendations:
            print(f"💡 {'; '.join(result.recommendations)}")


if __name__ == '__main__':
    main()
