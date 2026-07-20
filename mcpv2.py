#!/usr/bin/env python3
"""
MCPv2 – Secure, Cross-Provider P2P AI Agent Protocol
Supports Gemini, Claude, OpenAI, DeepSeek with full bidirectional translation.

SECURITY MODEL (read this before deploying):
MCPv2 uses a single shared HMAC secret between peers. Anyone holding the secret
can mint valid sessions and call any registered skill. This is a "trusted mesh"
model suitable for a closed set of agents you control (e.g. processes on a
private network, or over mTLS-terminated links). It is NOT per-agent identity/
authorization (no public-key auth, no scoped capabilities per peer) and the
`pay` skill is a stub, not a real payment rail. Do not expose an MCPv2 peer
directly to the open internet without a reverse proxy doing real authentication/
authorization and TLS termination in front of it.
"""

import os
import sys
import json
import base64
import argparse
import logging
import asyncio
import socket
import time
import hmac
import hashlib
import tempfile
from functools import lru_cache
from typing import Dict, Any, Callable, List, Optional, Union
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from collections import defaultdict
from enum import Enum
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from contextvars import ContextVar

import requests
import uvicorn
from fastapi import FastAPI, Request, Header, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError
from dotenv import load_dotenv

load_dotenv()

# ---------- Environment ----------
ENV_PORT = os.getenv("MCPV2_PORT", "8000")
ENV_SECRET = os.getenv("MCPV2_SECRET")
ENV_PUBLIC_IP = os.getenv("MCPV2_PUBLIC_IP")
ENV_LOG_LEVEL = os.getenv("MCPV2_LOG_LEVEL", "INFO").upper()
ENV_RATE_LIMIT = int(os.getenv("MCPV2_RATE_LIMIT", "200"))
ENV_SESSION_RATE_LIMIT = int(os.getenv("MCPV2_SESSION_RATE_LIMIT", "20"))
ENV_AUDIT_FILE = os.getenv("MCPV2_AUDIT_FILE", "mcpv2_audit.log")
ENV_LLM_MODE = os.getenv("MCPV2_LLM_MODE", "1") == "1"  # Now True by default
ENV_SESSION_TIMEOUT = int(os.getenv("MCPV2_SESSION_TIMEOUT", "3600"))
ENV_CLOCK_SKEW = int(os.getenv("MCPV2_CLOCK_SKEW", "300"))
ENV_TOOL_TIMEOUT = int(os.getenv("MCPV2_TOOL_TIMEOUT", "30"))
ENV_MEMORY_LIMIT_MB = int(os.getenv("MCPV2_MEMORY_LIMIT_MB", "256"))
ENV_FILE_STORE = os.path.abspath(os.getenv("MCPV2_FILE_STORE", "./mcpv2_files"))
ENV_ENABLE_MTLS = os.getenv("MCPV2_ENABLE_MTLS", "0") == "1"

logging.basicConfig(level=getattr(logging, ENV_LOG_LEVEL, logging.INFO),
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("mcpv2")

os.makedirs(ENV_FILE_STORE, exist_ok=True)

# ---------- Global State ----------
public_ip: Optional[str] = None
secret: Optional[str] = None
registry = None
current_session_id_var = ContextVar('current_session_id', default=None)
llm_sessions: Dict[str, Dict] = {}
sessions: Dict[str, Dict] = {}
_tasks_lock = asyncio.Lock()

# =============================================================================
# LAYER 5 – AI Agent Adapter Layer (Provider‑Native)
# =============================================================================
class AIProvider(Enum):
    CLAUDE = "claude"
    OPENAI = "openai"
    GEMINI = "gemini"
    DEEPSEEK = "deepseek"

@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters: Dict[str, Any]
    required: List[str] = field(default_factory=list)
    version: str = "1.0.0"
    strict: bool = True

class AIAdapter(ABC):
    @abstractmethod
    def to_native_tool(self, tool: ToolDefinition) -> Dict[str, Any]:
        pass
    @abstractmethod
    def from_native_call(self, native_call: Dict[str, Any]) -> Dict[str, Any]:
        pass
    @abstractmethod
    def to_native_response(self, result: Any) -> Dict[str, Any]:
        pass
    @abstractmethod
    def from_native_history(self, native_messages: List[Dict]) -> List[Dict]:
        pass
    @abstractmethod
    def to_native_history(self, unified_messages: List[Dict]) -> List[Dict]:
        pass

class ClaudeAdapter(AIAdapter):
    def to_native_tool(self, tool: ToolDefinition) -> Dict[str, Any]:
        return {"name": tool.name, "description": tool.description, "input_schema": {"type": "object", "properties": tool.parameters.get("properties", {}), "required": tool.required}}
    def from_native_call(self, native_call: Dict[str, Any]) -> Dict[str, Any]:
        return {"name": native_call.get("name"), "arguments": native_call.get("input", {})}
    def to_native_response(self, result: Any) -> Dict[str, Any]:
        return {"content": [{"type": "text", "text": str(result)}]}
    def from_native_history(self, native_messages: List[Dict]) -> List[Dict]:
        return [{"role": m.get("role"), "content": m.get("content", [{"text": ""}])[0].get("text", "")} for m in native_messages]
    def to_native_history(self, unified_messages: List[Dict]) -> List[Dict]:
        return [{"role": m.get("role"), "content": [{"type": "text", "text": m.get("content", "")}]} for m in unified_messages]

class OpenAIAdapter(AIAdapter):
    def to_native_tool(self, tool: ToolDefinition) -> Dict[str, Any]:
        return {"type": "function", "function": {"name": tool.name, "description": tool.description, "strict": tool.strict, "parameters": {"type": "object", "properties": tool.parameters.get("properties", {}), "required": tool.required, "additionalProperties": False}}}
    def from_native_call(self, native_call: Dict[str, Any]) -> Dict[str, Any]:
        func = native_call.get("function", {})
        return {"name": func.get("name"), "arguments": json.loads(func.get("arguments", "{}"))}
    def to_native_response(self, result: Any) -> Dict[str, Any]:
        return {"result": str(result)}
    def from_native_history(self, native_messages: List[Dict]) -> List[Dict]:
        return native_messages
    def to_native_history(self, unified_messages: List[Dict]) -> List[Dict]:
        return unified_messages

class GeminiAdapter(AIAdapter):
    def to_native_tool(self, tool: ToolDefinition) -> Dict[str, Any]:
        return {"functionDeclarations": [{"name": tool.name, "description": tool.description, "parameters": {"type": "object", "properties": tool.parameters.get("properties", {}), "required": tool.required}}]}
    def from_native_call(self, native_call: Dict[str, Any]) -> Dict[str, Any]:
        func = native_call.get("functionCall", {})
        return {"name": func.get("name"), "arguments": func.get("args", {})}
    def to_native_response(self, result: Any) -> Dict[str, Any]:
        return {"response": str(result)}
    def from_native_history(self, native_messages: List[Dict]) -> List[Dict]:
        unified = []
        for msg in native_messages:
            parts = msg.get("parts", [])
            content = " ".join(p.get("text", "") for p in parts)
            unified.append({"role": msg.get("role"), "content": content})
        return unified
    def to_native_history(self, unified_messages: List[Dict]) -> List[Dict]:
        return [{"role": m.get("role"), "parts": [{"text": m.get("content", "")}]} for m in unified_messages]

class DeepSeekAdapter(OpenAIAdapter):
    pass

ADAPTERS = {
    AIProvider.CLAUDE: ClaudeAdapter(),
    AIProvider.OPENAI: OpenAIAdapter(),
    AIProvider.GEMINI: GeminiAdapter(),
    AIProvider.DEEPSEEK: DeepSeekAdapter(),
}

def get_adapter(provider: AIProvider) -> AIAdapter:
    return ADAPTERS[provider]

# =============================================================================
# LAYER 5b – MCPv2 Core Session Layer
# =============================================================================
class MCPErrorCode:
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    INVALID_SESSION = -32001
    SKILL_NOT_FOUND = -32002
    SKILL_EXECUTION_ERROR = -32003
    TOOL_EXECUTION_ERROR = -32004
    RATE_LIMITED = -32005
    VERSION_MISMATCH = -32006
    FILE_NOT_FOUND = -32007
    PAYMENT_FAILED = -32008
    CAPABILITY_VIOLATION = -32009
    UNSUPPORTED_PROVIDER = -32010

class JsonRpcError(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None

class SlotRequest(BaseModel):
    jsonrpc: str = Field(default="2.0", frozen=True)
    id: Optional[Union[int, str]] = None
    method: str
    params: Optional[Dict[str, Any]] = None
    context: Optional[Dict[str, Any]] = None

class SlotResponse(BaseModel):
    jsonrpc: str = Field(default="2.0", frozen=True)
    id: Optional[Union[int, str]] = None
    result: Optional[Any] = None
    error: Optional[JsonRpcError] = None

class Skill(BaseModel):
    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Callable[..., Any]
    version: str = "1.0.0"
    provider: Optional[AIProvider] = None
    deprecated: bool = False
    timeout: int = ENV_TOOL_TIMEOUT
    memory_limit_mb: int = ENV_MEMORY_LIMIT_MB
    signature: Optional[str] = None

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Skill] = {}
        self._peer_id = "unknown"

    def set_peer_id(self, peer_id: str):
        self._peer_id = peer_id

    def register(self, skill: Skill) -> None:
        skill.signature = self._sign_skill(skill)
        self._tools[skill.name] = skill
        logger.info(f"Registered skill: {skill.name} v{skill.version}")

    def _sign_skill(self, skill: Skill) -> str:
        payload = f"{skill.name}:{skill.description}:{json.dumps(skill.input_schema)}:{self._peer_id}"
        return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()

    def get(self, name: str) -> Optional[Skill]:
        return self._tools.get(name)

    def list(self, provider: Optional[AIProvider] = None) -> List[Dict[str, Any]]:
        tools = self._tools.values()
        if provider:
            tools = [t for t in tools if t.provider is None or t.provider == provider]
        return [{"name": s.name, "description": s.description, "inputSchema": s.input_schema, "version": s.version, "deprecated": s.deprecated, "signature": s.signature} for s in tools]

    def call(self, name: str, arguments: Dict[str, Any], peer_id: str = None) -> Any:
        skill = self.get(name)
        if not skill:
            raise ValueError(f"Unknown skill: {name}")
        if skill.deprecated:
            logger.warning(f"Deprecated skill {name} called")
        sandbox = ToolSandbox(timeout=skill.timeout, memory_limit_mb=skill.memory_limit_mb)
        return sandbox.execute(name, skill.handler, arguments)

class ToolSandbox:
    def __init__(self, timeout: int = ENV_TOOL_TIMEOUT, memory_limit_mb: int = ENV_MEMORY_LIMIT_MB):
        self.timeout = timeout
        self.memory_limit_mb = memory_limit_mb

    def execute(self, tool_name: str, handler: Callable, arguments: Dict[str, Any]) -> Any:
        try:
            resource.setrlimit(resource.RLIMIT_AS, (self.memory_limit_mb * 1024 * 1024, self.memory_limit_mb * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (self.timeout, self.timeout + 5))
        except (ImportError, AttributeError):
            pass
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                return handler(**arguments)
            finally:
                os.chdir(old_cwd)

# ---------- Agent Card ----------
@dataclass
class AgentCard:
    name: str
    description: str
    version: str
    protocol_version: str = "2.1.0"
    transports: List[str] = field(default_factory=lambda: ["http"])
    skills: List[Dict[str, Any]] = field(default_factory=list)
    endpoints: Dict[str, str] = field(default_factory=dict)
    security: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {"name": self.name, "description": self.description, "version": self.version, "protocolVersion": self.protocol_version, "transports": self.transports, "skills": self.skills, "endpoints": self.endpoints, "security": self.security}

# ---------- Secure Session ----------
class SecureSession:
    @staticmethod
    def create(peer_ip: str, shared_secret: str) -> str:
        nonce = base64.b64encode(os.urandom(16)).decode('ascii')
        timestamp = str(int(time.time()))
        payload = f"{peer_ip}:{nonce}:{timestamp}"
        signature = hmac.new(shared_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        session_id = f"{base64.urlsafe_b64encode(payload.encode()).decode()}.{signature}"
        sessions[session_id] = {"created_at": time.time(), "expires_at": time.time() + ENV_SESSION_TIMEOUT, "peer_ip": peer_ip}
        return session_id

    @staticmethod
    def verify(session_id: str, shared_secret: str, client_ip: str) -> bool:
        try:
            if session_id in sessions:
                if time.time() > sessions[session_id]["expires_at"]:
                    del sessions[session_id]
                    return False
                if sessions[session_id]["peer_ip"] != client_ip:
                    return False
            parts = session_id.split('.')
            if len(parts) != 2:
                return False
            payload_b64, sig = parts
            payload = base64.urlsafe_b64decode(payload_b64.encode()).decode()
            ip, nonce, ts = payload.split(':')
            if ip != client_ip:
                return False
            if abs(int(ts) - int(time.time())) > ENV_CLOCK_SKEW:
                return False
            expected = hmac.new(shared_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(sig, expected)
        except Exception:
            return False

# ---------- Rate Limiter ----------
class RateLimiter:
    def __init__(self, rate: int = 200):
        self.rate = rate
        self.buckets: Dict[str, Dict] = defaultdict(lambda: {"tokens": rate, "last": time.time()})
        self._lock = asyncio.Lock()

    async def allow(self, key: str) -> bool:
        async with self._lock:
            now = time.time()
            bucket = self.buckets[key]
            elapsed = now - bucket["last"]
            bucket["tokens"] = min(self.rate, bucket["tokens"] + elapsed * self.rate)
            bucket["last"] = now
            if bucket["tokens"] >= 1:
                bucket["tokens"] -= 1
                return True
            return False

rate_limiter = RateLimiter(ENV_RATE_LIMIT)
session_rate_limiter = RateLimiter(ENV_SESSION_RATE_LIMIT)

# ---------- Audit Logger ----------
class AuditLogger:
    def __init__(self, filename: str = ENV_AUDIT_FILE):
        self.filename = filename
        self._lock = asyncio.Lock()

    async def log(self, entry: Dict) -> None:
        entry["timestamp"] = datetime.utcnow().isoformat()
        async with self._lock:
            with open(self.filename, 'a') as f:
                f.write(json.dumps(entry) + '\n')

audit_logger = AuditLogger()

# ---------- Skills ----------
def ask(query: str) -> Dict[str, Any]:
    session_id = current_session_id_var.get()
    if ENV_LLM_MODE and session_id:
        if session_id not in llm_sessions:
            llm_sessions[session_id] = {'history': [], 'created': time.time()}
        session = llm_sessions[session_id]
        session['history'].append(query)
        if len(session['history']) == 1:
            return {"answer": f"First question: '{query}'. I'll remember this conversation.", "session": session_id}
        else:
            prev = session['history'][-2]
            return {"answer": f"Previously you asked '{prev}'. Now you ask '{query}'. I'm maintaining context.", "session": session_id}
    else:
        return {"message": f"Generic response to: {query}"}

def upload_file(filename: str, content_b64: str) -> Dict[str, Any]:
    try:
        content = base64.b64decode(content_b64)
        safe_filename = os.path.basename(filename)
        if not safe_filename:
            return {"error": "Invalid filename"}
        filepath = os.path.join(ENV_FILE_STORE, safe_filename)
        with open(filepath, 'wb') as f:
            f.write(content)
        return {"status": "success", "filename": safe_filename, "size": len(content), "path": filepath}
    except Exception as e:
        return {"error": f"Upload failed: {str(e)}"}

def list_files() -> Dict[str, Any]:
    try:
        files = []
        for f in os.listdir(ENV_FILE_STORE):
            path = os.path.join(ENV_FILE_STORE, f)
            if os.path.isfile(path):
                files.append({"name": f, "size": os.path.getsize(path), "modified": datetime.fromtimestamp(os.path.getmtime(path)).isoformat()})
        return {"files": files}
    except Exception as e:
        return {"error": f"List failed: {str(e)}"}

def process_instructions(filename: str) -> Dict[str, Any]:
    safe_filename = os.path.basename(filename)
    filepath = os.path.join(ENV_FILE_STORE, safe_filename)
    if not os.path.exists(filepath):
        return {"error": f"File {safe_filename} not found"}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return {"filename": safe_filename, "content": content, "line_count": len(content.splitlines()), "char_count": len(content)}
    except Exception as e:
        return {"error": f"Processing failed: {str(e)}"}

def delete_file(filename: str) -> Dict[str, Any]:
    safe_filename = os.path.basename(filename)
    filepath = os.path.join(ENV_FILE_STORE, safe_filename)
    if not os.path.exists(filepath):
        return {"error": f"File {safe_filename} not found"}
    try:
        os.remove(filepath)
        return {"status": "deleted", "filename": safe_filename}
    except Exception as e:
        return {"error": f"Deletion failed: {str(e)}"}

def get_skill(name: str, file: str, script: str, ref: str) -> Dict[str, Any]:
    return {"skill_name": name, "file": file, "script": script, "reference": ref, "status": "available"}

def ping(message: str = "ping") -> Dict[str, Any]:
    return {"echo": message, "timestamp": datetime.utcnow().isoformat(), "latency_ms": 0}

def pay(amount: float, currency: str = "USD", recipient: str = None) -> Dict[str, Any]:
    return {"status": "pending", "amount": amount, "currency": currency, "recipient": recipient or "unknown", "transaction_id": f"txn_{int(time.time())}_{os.urandom(4).hex()}"}

def negotiate(capabilities: Dict[str, Any]) -> Dict[str, Any]:
    return {"status": "negotiated", "accepted_capabilities": capabilities, "server_capabilities": {"supports_streaming": True, "max_batch_size": 100, "protocol_version": "2.1.0"}}

def translate_history(history: List[Dict], from_provider: str, to_provider: str) -> Dict[str, Any]:
    try:
        from_enum = AIProvider(from_provider.lower())
        to_enum = AIProvider(to_provider.lower())
    except ValueError:
        return {"error": f"Unsupported provider: {from_provider} or {to_provider}"}
    adapter_from = get_adapter(from_enum)
    adapter_to = get_adapter(to_enum)
    unified = adapter_from.from_native_history(history)
    native = adapter_to.to_native_history(unified)
    return {"translated_history": native}

def create_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.set_peer_id(public_ip or "unknown")
    registry.register(Skill(name="ask", description="Ask a generic question; maintains context.", input_schema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}, handler=ask, version="1.0.0"))
    registry.register(Skill(name="upload_file", description="Upload a file (base64 encoded) to the peer's file store.", input_schema={"type": "object", "properties": {"filename": {"type": "string"}, "content_b64": {"type": "string"}}, "required": ["filename", "content_b64"]}, handler=upload_file, version="1.0.0"))
    registry.register(Skill(name="list_files", description="List all files in the file store.", input_schema={"type": "object", "properties": {}}, handler=list_files, version="1.0.0"))
    registry.register(Skill(name="process_instructions", description="Process an uploaded instructions.md file.", input_schema={"type": "object", "properties": {"filename": {"type": "string"}}, "required": ["filename"]}, handler=process_instructions, version="1.0.0"))
    registry.register(Skill(name="delete_file", description="Delete a file from the file store.", input_schema={"type": "object", "properties": {"filename": {"type": "string"}}, "required": ["filename"]}, handler=delete_file, version="1.0.0"))
    registry.register(Skill(name="get_skill", description="Retrieve a skill definition.", input_schema={"type": "object", "properties": {"name": {"type": "string"}, "file": {"type": "string"}, "script": {"type": "string"}, "ref": {"type": "string"}}, "required": ["name"]}, handler=get_skill, version="1.0.0"))
    registry.register(Skill(name="ping", description="Check connectivity with a ping.", input_schema={"type": "object", "properties": {"message": {"type": "string"}}}, handler=ping, version="1.0.0"))
    registry.register(Skill(name="pay", description="Initiate a payment request.", input_schema={"type": "object", "properties": {"amount": {"type": "number"}, "currency": {"type": "string"}, "recipient": {"type": "string"}}, "required": ["amount"]}, handler=pay, version="1.0.0"))
    registry.register(Skill(name="negotiate", description="Negotiate capabilities with the peer.", input_schema={"type": "object", "properties": {"capabilities": {"type": "object"}}, "required": ["capabilities"]}, handler=negotiate, version="1.0.0"))
    registry.register(Skill(name="translate_history", description="Translate conversation history between provider formats.", input_schema={"type": "object", "properties": {"history": {"type": "array"}, "from_provider": {"type": "string"}, "to_provider": {"type": "string"}}, "required": ["history", "from_provider", "to_provider"]}, handler=translate_history, version="1.0.0"))
    return registry

# ---------- Handlers ----------
def handle_initialize(params: Optional[Dict]) -> Dict:
    client_version = params.get("protocolVersion", "1.0.0") if params else "1.0.0"
    server_version = "2.1.0"
    c_major = int(client_version.split('.')[0]) if client_version else 0
    s_major = int(server_version.split('.')[0]) if server_version else 0
    if c_major != s_major:
        return {"error": {"code": MCPErrorCode.VERSION_MISMATCH, "message": f"Protocol version mismatch: client {client_version}, server {server_version}"}}
    return {"protocolVersion": server_version, "serverInfo": {"name": "MCPv2 Peer", "version": "2.0.0", "providers": [p.value for p in AIProvider], "rateLimits": {"requests_per_second": ENV_RATE_LIMIT}, "transports": ["http", "https"], "capabilities": {"batching": True, "streaming": True, "tasks": True, "file_transfer": True, "payments": True, "history_translation": True}}}

def handle_tools_list(registry: ToolRegistry, provider: Optional[str] = None) -> Dict:
    if provider:
        try:
            prov = AIProvider(provider.lower())
            tools = registry.list(prov)
        except ValueError:
            tools = registry.list()
    else:
        tools = registry.list()
    return {"tools": tools}

def handle_tools_call(params: Dict, registry: ToolRegistry) -> Dict:
    name = params.get("name")
    arguments = params.get("arguments", {})
    try:
        result = registry.call(name, arguments)
        return {"content": [{"type": "text", "text": str(result)}]}
    except ValueError as e:
        raise ValueError(f"Tool error: {str(e)}")
    except PermissionError as e:
        raise PermissionError(f"Authorization error: {str(e)}")
    except Exception as e:
        raise RuntimeError(f"Execution error: {str(e)}")

async def process_slot_async(slot_data: Dict, registry: ToolRegistry, session_id: str = None) -> SlotResponse:
    if session_id:
        current_session_id_var.set(session_id)
    slot_id = slot_data.get("id")
    try:
        slot = SlotRequest(**slot_data)
        provider_hint = slot.context.get("provider") if slot.context else None

        if slot.method == "initialize":
            result = handle_initialize(slot.params)
            if "error" in result:
                return SlotResponse(id=slot_id, error=JsonRpcError(code=result["error"]["code"], message=result["error"]["message"]))
        elif slot.method == "tools/list":
            provider = slot.params.get("_provider") if slot.params else None
            result = handle_tools_list(registry, provider)
        elif slot.method == "tools/call":
            result = handle_tools_call(slot.params, registry)
            if provider_hint:
                try:
                    adapter = get_adapter(AIProvider(provider_hint.lower()))
                    result = adapter.to_native_response(result)
                except ValueError:
                    return SlotResponse(id=slot_id, error=JsonRpcError(code=MCPErrorCode.UNSUPPORTED_PROVIDER, message=f"Unsupported provider: {provider_hint}", data={"supported": [p.value for p in AIProvider]}))
        else:
            return SlotResponse(id=slot_id, error=JsonRpcError(code=MCPErrorCode.METHOD_NOT_FOUND, message="Method not found"))
        return SlotResponse(id=slot_id, result=result)
    except ValidationError as e:
        logger.warning(f"Validation error for slot {slot_id}: {e}")
        return SlotResponse(id=slot_id, error=JsonRpcError(code=MCPErrorCode.INVALID_REQUEST, message="Invalid Request", data=str(e)))
    except ValueError as e:
        return SlotResponse(id=slot_id, error=JsonRpcError(code=MCPErrorCode.TOOL_EXECUTION_ERROR, message=str(e)))
    except PermissionError as e:
        return SlotResponse(id=slot_id, error=JsonRpcError(code=MCPErrorCode.CAPABILITY_VIOLATION, message=str(e)))
    except Exception as e:
        logger.exception(f"Unexpected error slot {slot_id}")
        return SlotResponse(id=slot_id, error=JsonRpcError(code=MCPErrorCode.INTERNAL_ERROR, message=f"Internal error: {str(e)}"))

# ---------- IP Auto-Detection ----------
@lru_cache(maxsize=1)
def fetch_public_ip() -> str:
    for attempt in range(2):
        try:
            response = requests.get("https://api.ipify.org?format=json", timeout=5)
            response.raise_for_status()
            ip = response.json()["ip"]
            logger.info(f"Public IP: {ip}")
            return ip
        except Exception as e:
            if attempt == 0:
                logger.warning(f"IP fetch retry: {e}")
                time.sleep(0.5)
            else:
                logger.warning(f"IP fetch failed: {e}, using 127.0.0.1")
                return "127.0.0.1"
    return "127.0.0.1"

def generate_secret() -> str:
    return base64.b64encode(os.urandom(32)).decode('ascii')

# ---------- FastAPI Application ----------
async def validate_session(request: Request, sessionId: str = Header(...)) -> str:
    if secret is None:
        raise HTTPException(status_code=500, detail="Server not initialized")
    client_ip = request.client.host
    if not SecureSession.verify(sessionId, secret, client_ip):
        raise HTTPException(status_code=401, detail="Invalid sessionId")
    if not await session_rate_limiter.allow(sessionId):
        raise HTTPException(status_code=429, detail="Session rate limit exceeded")
    return sessionId

@asynccontextmanager
async def lifespan(app: FastAPI):
    global public_ip, secret, registry
    public_ip = ENV_PUBLIC_IP or fetch_public_ip()
    secret = ENV_SECRET or generate_secret()
    registry = create_default_registry()
    logger.info("=" * 60)
    logger.info(f"🌐 Public IP:   {public_ip}")
    logger.info(f"🔑 Secret:      {secret[:8]}...")
    logger.info(f"🚦 Rate limit:  {ENV_RATE_LIMIT} req/s")
    logger.info(f"⏱️  Session timeout: {ENV_SESSION_TIMEOUT}s")
    logger.info(f"📁 File store:  {ENV_FILE_STORE}")
    logger.info(f"🤖 LLM mode:    {ENV_LLM_MODE}")
    logger.info(f"🔒 mTLS:        {ENV_ENABLE_MTLS}")
    if hasattr(app.state, "port") and app.state.port:
        logger.info(f"🧭 MCPv2 address: mcpv2://{public_ip}:{app.state.port}/mcpv2")
    logger.info("=" * 60)
    yield

app = FastAPI(title="MCPv2 Peer", version="2.0.0", lifespan=lifespan)

# ---------- Public Endpoints ----------
@app.get("/mcpv2")
async def root_info():
    """Return the peer's MCPv2 address template and session endpoint."""
    return {
        "peer": f"mcpv2://{public_ip}:{app.state.port}/mcpv2?sessionId=<your_session_id>",
        "session_endpoint": "/mcpv2/session",
        "info": "Use GET /mcpv2/session to obtain a fresh sessionId."
    }

@app.get("/mcpv2/commands")
async def list_commands():
    """Return a structured list of MCPv2 CLI commands."""
    return {
        "commands": [
            {
                "name": "ReadyTo",
                "syntax": "ReadyTo [--port <port>] [--secret <secret>] [--public-ip <ip>] [--bind-host <ip>] [--llm-mode]",
                "description": "Start a local MCPv2 peer and print its mcpv2:// address.",
                "example": "ReadyTo --port 9000 --secret mySecret --public-ip 203.0.113.42"
            },
            {
                "name": "StopTo",
                "syntax": "StopTo <port|address>",
                "description": "Stop a peer previously started by ReadyTo.",
                "example": "StopTo 8000   or   StopTo mcpv2://127.0.0.1:8000/mcpv2"
            },
            {
                "name": "ConnectTo",
                "syntax": "ConnectTo <address>",
                "description": "Perform a full authentication round-trip with a remote peer.",
                "example": "ConnectTo mcpv2://127.0.0.1:8000/mcpv2"
            },
            {
                "name": "SentTo",
                "syntax": "SentTo <content> <address> [--provider <provider>]",
                "description": "Send a prompt (plain text) or a file (path) to the remote peer.",
                "example": "SentTo \"Hello, how are you?\" mcpv2://127.0.0.1:8000/mcpv2 --provider claude",
                "example_file": "SentTo instructions.md mcpv2://127.0.0.1:8000/mcpv2"
            },
            {
                "name": "PayTo",
                "syntax": "PayTo <amount> <address>",
                "description": "Request a stub payment from the remote peer.",
                "example": "PayTo 10.5 mcpv2://127.0.0.1:8000/mcpv2"
            },
            {
                "name": "PingTo",
                "syntax": "PingTo <address>",
                "description": "Measure round-trip latency and echo a ping.",
                "example": "PingTo mcpv2://127.0.0.1:8000/mcpv2"
            },
            {
                "name": "SendTo",
                "syntax": "SendTo <content> <address> [--provider <provider>]",
                "description": "Alias for SentTo (same syntax).",
                "example": "SendTo \"Hello\" mcpv2://127.0.0.1:8000/mcpv2"
            },
            {
                "name": "StopPeer",
                "syntax": "StopPeer <port|address>",
                "description": "Alias for StopTo (same syntax).",
                "example": "StopPeer 8000"
            },
            {
                "name": "help",
                "syntax": "help",
                "description": "Show this help in the CLI.",
                "example": "help"
            },
            {
                "name": "exit/quit",
                "syntax": "exit or quit",
                "description": "Exit the CLI (stops any peers started by ReadyTo).",
                "example": "exit"
            }
        ],
        "address_format": "mcpv2://<host>:<port>/mcpv2?sessionId=<sessionId>",
        "provider_flags": "claude | openai | gemini | deepseek",
        "notes": "MCPv2 peers bind directly to their public IP by default. If behind NAT, use --public-ip <ip> and --bind-host 0.0.0.0."
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "public_ip": public_ip, "secret_preview": secret[:8] + "..." if secret else None, "providers": [p.value for p in AIProvider], "rate_limit": ENV_RATE_LIMIT, "llm_mode": ENV_LLM_MODE, "session_timeout": ENV_SESSION_TIMEOUT, "active_sessions": len(sessions), "file_store": ENV_FILE_STORE, "mtls_enabled": ENV_ENABLE_MTLS, "uptime": time.time() - app.state.start_time if hasattr(app.state, "start_time") else 0}

@app.get("/mcpv2/session")
async def create_session(request: Request):
    client_ip = request.client.host
    session_id = SecureSession.create(client_ip, secret)
    return {"sessionId": session_id}

@app.get("/mcpv2/agent-card")
async def get_agent_card():
    card = AgentCard(name=f"MCPv2 Peer at {public_ip}", description="MCPv2 AI Agent Peer with Full P2P + Cross-Provider Support", version="2.0.0", protocol_version="2.1.0", transports=["http", "https"], skills=registry.list(), endpoints={"mcpv2": "/mcpv2", "session": "/mcpv2/session", "health": "/health", "agent_card": "/mcpv2/agent-card"}, security={"auth_type": "hmac_session", "supports_mtls": ENV_ENABLE_MTLS, "session_timeout": ENV_SESSION_TIMEOUT, "rate_limit": ENV_RATE_LIMIT})
    return JSONResponse(content=card.to_dict())

@app.post("/mcpv2", dependencies=[Depends(validate_session)])
async def mcpv2_endpoint(request: Request, sessionId: str = Header(...)):
    try:
        body = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    if not isinstance(body, list):
        raise HTTPException(status_code=400, detail="Payload must be a JSON array")
    tasks = [process_slot_async(item, registry, sessionId) for item in body]
    responses = await asyncio.gather(*tasks)
    for req, resp in zip(body, responses):
        await audit_logger.log({"sessionId": sessionId, "method": req.get("method"), "skill": req.get("params", {}).get("name") if req.get("method") == "tools/call" else None, "status": "success" if not resp.get("error") else "error"})
    return JSONResponse(content=[r.dict(exclude_none=True) for r in responses])

@app.post("/mcpv2/ai/{provider}")
async def ai_agent_endpoint(provider: str, request: Request, sessionId: str = Header(...)):
    if secret is None:
        raise HTTPException(status_code=500, detail="Server not initialized")
    try:
        prov = AIProvider(provider.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    adapter = get_adapter(prov)
    body = await request.json()
    tool_calls = []
    if prov == AIProvider.CLAUDE:
        tool_calls = body.get("tool_calls", [])
    elif prov in [AIProvider.OPENAI, AIProvider.DEEPSEEK]:
        tool_calls = body.get("tool_calls", [])
    elif prov == AIProvider.GEMINI:
        tool_calls = [body] if body.get("functionCall") else []
    results = []
    for tc in tool_calls:
        unified = adapter.from_native_call(tc)
        try:
            result = registry.call(unified["name"], unified.get("arguments", {}))
            results.append(adapter.to_native_response(result))
        except Exception as e:
            results.append({"error": str(e)})
    return JSONResponse(content={"results": results})

# ---------- Client Functions ----------
_http_session = None

def get_http_session():
    global _http_session
    if _http_session is None:
        _http_session = requests.Session()
        _http_session.headers.update({"Content-Type": "application/json"})
    return _http_session

def send_batch(target_url: str, slots: list, session_id: str = None) -> list:
    if session_id is None:
        session_id = SecureSession.create(public_ip, secret)
    headers = {"sessionId": session_id}
    if not target_url.endswith("/mcpv2"):
        target_url = target_url.rstrip("/") + "/mcpv2"
    try:
        sess = get_http_session()
        resp = sess.post(target_url, json=slots, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Batch send failed: {e}")
        raise

def find_available_port(start_port: int, max_attempts: int = 10) -> int:
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('', port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No available port in range {start_port}-{start_port+max_attempts-1}")

# ---------- CLI Entry Point ----------
def main():
    global public_ip, secret, registry
    parser = argparse.ArgumentParser(description="MCPv2 Peer – Full P2P AI Agent Protocol")
    parser.add_argument("--port", type=int, default=int(ENV_PORT), help="TCP port")
    parser.add_argument("--secret", help="Secret key (auto-generated)")
    parser.add_argument("--bind-host", help="Bind address (default: same as --public-ip; use 0.0.0.0 to bind all interfaces)")
    parser.add_argument("--public-ip", help="Override public IP")
    parser.add_argument("--port-file", help="Write the actual bound port to this file (for test harness)")
    parser.add_argument("--target", help="Target URL to send a batch (client mode)")
    parser.add_argument("--slots", type=int, default=3, help="Number of slots")
    parser.add_argument("--skills", help="JSON file with custom skills")
    parser.add_argument("--version", action="version", version="MCPv2 2.1.0")
    parser.add_argument("--log-level", default=ENV_LOG_LEVEL, help="Log level")
    args = parser.parse_args()

    logging.getLogger().setLevel(args.log_level.upper())

    public_ip = args.public_ip or fetch_public_ip()
    secret = args.secret or generate_secret()
    registry = create_default_registry()

    # Determine bind_host: default = public_ip (never 0.0.0.0), but allow override.
    bind_host = args.bind_host if args.bind_host is not None else public_ip

    if args.skills:
        try:
            with open(args.skills, 'r') as f:
                skills_data = json.load(f)
            if "skills" not in skills_data:
                raise ValueError("Missing 'skills' key")
            for skill_def in skills_data["skills"]:
                def make_handler(name):
                    def handler(**kwargs):
                        return {"message": f"Executed {name} with args {kwargs}"}
                    return handler
                provider = None
                if "provider" in skill_def:
                    try:
                        provider = AIProvider(skill_def["provider"].lower())
                    except ValueError:
                        pass
                skill = Skill(
                    name=skill_def["name"],
                    description=skill_def.get("description", ""),
                    input_schema=skill_def.get("inputSchema", {"type": "object", "properties": {}}),
                    handler=make_handler(skill_def["name"]),
                    version=skill_def.get("version", "1.0.0"),
                    provider=provider,
                    deprecated=skill_def.get("deprecated", False),
                    timeout=skill_def.get("timeout", ENV_TOOL_TIMEOUT),
                    memory_limit_mb=skill_def.get("memory_limit_mb", ENV_MEMORY_LIMIT_MB)
                )
                registry.register(skill)
            logger.info("✅ Custom skills loaded.")
        except Exception as e:
            logger.error(f"Failed to load skills: {e}")
            sys.exit(1)

    if args.target:
        slots = [
            SlotRequest(id=1, method="initialize", params={"protocolVersion": "2.1.0"}).dict(),
            SlotRequest(id=2, method="tools/list", params={}).dict(),
            SlotRequest(id=3, method="tools/call", params={"name": "ask", "arguments": {"query": "Hello"}}).dict()
        ]
        for i in range(4, args.slots + 1):
            slots.append(SlotRequest(id=i, method="tools/call", params={"name": "get_skill", "arguments": {"name": f"skill_{i}", "file": f"file_{i}.md", "script": "script.sh", "ref": f"ref_{i}"}}).dict())
        logger.info(f"Sending {len(slots)} slots to {args.target} ...")
        try:
            response = send_batch(args.target, slots)
            print(json.dumps(response, indent=2))
        except Exception as e:
            logger.error(f"Batch failed: {e}")
            sys.exit(1)
    else:
        try:
            port = find_available_port(args.port)
            if port != args.port:
                logger.info(f"Port {args.port} busy, using {port}")
        except RuntimeError as e:
            logger.error(e)
            sys.exit(1)
        if args.port_file:
            with open(args.port_file, 'w') as f:
                f.write(str(port))
        # Validate that the bind address is actually assigned to a local interface
        # (unless it's 0.0.0.0, which binds all interfaces).
        if bind_host != "0.0.0.0":
            try:
                socket.gethostbyname(bind_host)
            except socket.gaierror:
                logger.error(f"❌ Bind address '{bind_host}' does not resolve to a local interface. "
                             f"Use --bind-host 0.0.0.0 to bind all interfaces, or ensure '{bind_host}' "
                             f"is assigned to this machine.")
                sys.exit(1)
        app.state.port = port
        app.state.public_ip = public_ip
        app.state.start_time = time.time()
        logger.info(f"Starting MCPv2 server on {bind_host}:{port} (advertising {public_ip})...")
        uvicorn.run(app, host=bind_host, port=port, log_level=args.log_level.lower())

if __name__ == "__main__":
    main()