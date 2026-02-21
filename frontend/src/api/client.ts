import axios from 'axios';

// Default to localhost:8765 if not specified
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8765/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // Handle global errors here
    console.error('API Error:', error);
    return Promise.reject(error);
  }
);

export interface ProjectOverview {
  project: string;
  binaries_count: number;
  analysis_status: string;
  backend: string;
  capabilities: Record<string, boolean>;
}

export interface BinarySummary {
  binary_name: string;
  sha256?: string;
  arch?: string;
  file_format?: string;
  size?: number;
  function_count?: number;
  created_at?: string;
  [key: string]: unknown;
}

export interface BinaryMetadata {
  binary_name: string;
  arch?: string;
  processor?: string;
  address_width?: string;
  size?: number;
  format?: string;
  image_base?: string;
  endian?: string;
  created_at?: string;
  counts?: {
    functions: number;
    user_functions?: number;
    library_functions?: number;
    imports: number;
    exports: number;
    symbols: number;
    strings: number;
    segments: number;
  };
  hashes?: {
    sha256?: string;
    md5?: string;
    crc32?: string;
  };
  compiler?: {
    compiler_name?: string;
    compiler_abbr?: string;
  };
  libraries?: string[];
  [key: string]: unknown;
}

export interface BinaryFunction {
  name: string;
  demangled_name?: string;
  address: string;
  start_address: string;
  end_address: string;
  size: number;
  is_thunk: boolean;
  is_library: boolean;
}

export interface FunctionCallerRef {
  caller_address: string;
  caller_name?: string | null;
  call_count: number;
}

export interface FunctionCalleeRef {
  call_site_address: string;
  callee_address: string;
  callee_name?: string | null;
  call_type?: string | null;
}

export interface PaginatedResponse<T> {
  results: T[];
  has_more: boolean;
  next_offset?: number | null;
}

export interface PseudocodeResult {
  function_address: string;
  name: string;
  pseudocode: string;
}

// Audit Interfaces

export interface AuditPlan {
  id: number;
  // Common fields
  title: string;
  description: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  created_at: number;
  updated_at: number;
  notes?: string;
  
  // Specific to Tasks (Agent/Verification)
  plan_id?: number; // The new field for parent link
  plan_type?: string; // 'audit_plan', 'agent_plan', 'verification_plan' (legacy/compat)
  task_type?: 'agent_task' | 'verification_task'; // New field
  binary_name?: string;
  summary?: string;
}

export interface AuditMacroPlan {
  id: number;
  title: string;
  description: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  notes?: string;
  created_at: number;
  updated_at: number;
  type: 'audit_plan';
}

export interface MacroPlanCreate {
  title: string;
  description: string;
}

export interface TaskCreate {
  title: string;
  description: string;
  plan_id: number;
  binary_name: string;
  task_type?: 'agent_task' | 'verification_task';
}

export interface AuditTask {
  id: number;
  plan_id: number;
  title: string;
  description: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  binary_name?: string;
  task_type: 'agent_task' | 'verification_task';
  summary?: string;
  notes?: string;
  created_at: number;
  updated_at: number;
  
  // Computed/Compat fields
  type?: string;
}

export interface AuditLog {
  id: number;
  plan_id?: number;
  message: string;
  timestamp: number;
}

export interface AuditMessage {
  id: number;
  session_id: string;
  role: 'user' | 'assistant' | 'system' | 'tool_call' | 'tool_result';
  content: string;
  timestamp: number;
}

export interface AuditStatus {
  status: 'idle' | 'running' | 'completed' | 'failed' | 'not_initialized';
  error?: string;
  current_session_id?: string;
  current_agent?: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Category = 
  | 'buffer_overflow' 
  | 'format_string' 
  | 'integer_overflow' 
  | 'use_after_free' 
  | 'double_free' 
  | 'memory_disclosure' 
  | 'crypto_weak' 
  | 'hardcoded_secret' 
  | 'injection' 
  | 'path_traversal' 
  | 'authentication' 
  | 'authorization' 
  | 'anti_debug' 
  | 'anti_vm' 
  | 'packing' 
  | 'other';

export type VerificationStatus = 
  | 'unverified' 
  | 'confirmed' 
  | 'false_positive' 
  | 'needs_review' 
  | 'inconclusive';

export type NoteType = 
  | 'vulnerability' 
  | 'behavior' 
  | 'function_summary' 
  | 'data_structure' 
  | 'control_flow' 
  | 'crypto_usage' 
  | 'obfuscation' 
  | 'io_operation' 
  | 'general';

export type Confidence = 'high' | 'medium' | 'low' | 'speculative';

export interface Note {
  note_id: number;
  binary_name: string;
  title?: string;
  function_name?: string | null;
  address?: number | null;
  note_type: NoteType;
  content: string;
  confidence: Confidence;
  tags?: string[] | null;
  created_at: string;
  updated_at: string;
}

export interface Vulnerability {
  id: number;
  note_id: number;
  binary_name: string;
  title?: string;
  function_name?: string | null;
  address?: number | null;
  severity: Severity;
  category: Category;
  description: string;
  evidence?: string | null;
  cvss?: number | null;
  exploitability?: string | null;
  created_at: string;
  verification_status?: VerificationStatus;
  verification_details?: string | null;
}

export const auditApi = {
  getMacroPlans: async (status?: string) => {
    const params: Record<string, string> = {};
    if (status) params.status = status;
    const res = await apiClient.get<AuditMacroPlan[]>('/audit/macro-plans', { params });
    return res.data.map(p => ({
        ...p,
        plan_type: 'audit_plan',
        // Ensure id is number
        id: Number(p.id)
    })) as AuditPlan[];
  },

  createMacroPlan: async (data: MacroPlanCreate) => {
    const res = await apiClient.post<{ plan_id: number }>('/audit/macro-plans', data);
    return res.data;
  },

  getTasks: async () => {
    const res = await apiClient.get<AuditTask[]>('/audit/tasks');
    return res.data.map(t => ({
        ...t,
        plan_type: t.task_type === 'verification_task' ? 'verification_plan' : 'agent_plan',
        id: Number(t.id)
    })) as AuditPlan[];
  },

  createTask: async (data: TaskCreate) => {
    const res = await apiClient.post<{ task_id: number }>('/audit/tasks', data);
    return res.data;
  },

  getCompletedTasks: async () => {
    const res = await apiClient.get<AuditTask[]>('/audit/tasks');
    const completed = res.data.filter(t => t.status === 'completed');
    return completed.map(t => ({
        ...t,
        plan_type: t.task_type === 'verification_task' ? 'verification_plan' : 'agent_plan',
        id: Number(t.id)
    })) as AuditPlan[];
  },

  getTask: async (taskId: number) => {
    const res = await apiClient.get<AuditTask>(`/audit/task/${taskId}`);
    return {
      ...res.data,
      plan_type: res.data.task_type === 'verification_task' ? 'verification_plan' : 'agent_plan',
      id: Number(res.data.id)
    } as AuditPlan;
  },
   
  getLogs: async (limit = 50) => {
    const res = await apiClient.get<AuditLog[]>('/audit/logs', { params: { limit } });
    return res.data;
  },
  
  getMessages: async (sessionId?: string, limit = 100) => {
    const params = { session_id: sessionId, limit };
    const res = await apiClient.get<AuditMessage[]>('/audit/messages', { params });
    return res.data;
  },

  getSessions: async () => {
    const res = await apiClient.get<Array<{session_id: string, start_time: number, message_count: number}>>('/audit/sessions');
    return res.data;
  },

  streamMessages: (sessionId: string, onMessage: (msg: { role: string; content: string }) => void, onEnd?: () => void, onError?: (err: Error) => void) => {
    const baseUrl = API_BASE_URL.replace('/api/v1', '');
    const url = `${baseUrl}/api/v1/audit/stream/${sessionId}`;
    
    const eventSource = new EventSource(url);
    
    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'session_end') {
          onEnd?.();
          eventSource.close();
        } else {
          onMessage(data);
        }
      } catch (e) {
        console.error('Failed to parse SSE message:', e);
      }
    };
    
    eventSource.onerror = (err) => {
      console.error('SSE error:', err);
      onError?.(new Error('Connection lost'));
      eventSource.close();
    };
    
    return {
      close: () => eventSource.close()
    };
  },

  getNotes: async (binaryName?: string, limit = 50) => {
    const params = { binary_name: binaryName, limit };
    const res = await apiClient.get<Note[]>('/audit/notes', { params });
    return res.data;
  },

  getVulnerabilities: async (binaryName?: string, severity?: string) => {
    const params = { binary_name: binaryName, severity };
    const res = await apiClient.get<Vulnerability[]>('/audit/vulnerabilities', { params });
    return res.data;
  },

  getStatus: async () => {
    const res = await apiClient.get<AuditStatus>('/audit/status');
    return res.data;
  },
  
  getUserPrompt: async () => {
    const res = await apiClient.get<{content: string}>('/config/user-prompt');
    return res.data;
  },

  updateUserPrompt: async (content: string) => {
    const res = await apiClient.post('/config/user-prompt', { content });
    return res.data;
  },

  start: async () => {
    const res = await apiClient.post('/audit/start');
    return res.data;
  },
  
  stop: async () => {
    const res = await apiClient.post('/audit/stop');
    return res.data;
  }
};

export interface BinaryString {
  address: string;
  string: string;
  encoding: string;
  length: number;
  section?: string;
}

export interface BinaryImport {
  library: string;
  name: string;
  ordinal: number;
  address: string;
  thunk_address: string;
}

export interface BinaryExport {
  name: string;
  ordinal: number;
  address: string;
  forwarder?: string;
}

export interface BinarySymbol {
  name: string;
  demangled_name?: string | null;
  kind: string;
  address: string;
  size: number;
}

export interface BinarySegment {
  name: string;
  start_address: string;
  end_address: string;
  size: number;
  permissions: string;
  file_offset: number;
  type: string;
}

export interface ResolveAddressResult {
  address: string;
  function?: BinaryFunction;
  symbol?: unknown;
  segment?: unknown;
  section?: unknown;
  string_ref?: unknown;
  data_item?: unknown;
  is_code: boolean;
  is_data: boolean;
}

export interface McpToolProperty {
  type?: string;
  description?: string;
  [key: string]: unknown;
}

export interface XrefToItem {
  from_address: string;
  from_function?: string | null;
  from_function_name?: string | null;
  xref_type?: string | null;
  operand_index?: number | null;
  [key: string]: unknown;
}

export interface XrefFromItem {
  to_address: string;
  to_function?: string | null;
  xref_type?: string | null;
  [key: string]: unknown;
}

export interface McpTool {
  name: string;
  description: string;
  inputSchema: {
    type: string;
    properties: Record<string, McpToolProperty>;
    required?: string[];
  };
}

export interface NoteCreate {
  binary_name: string;
  content: string;
  note_type: string;
  title?: string;
  function_name?: string | null;
  address?: string | number | null;
  tags?: string | null;
  confidence?: string;
}

export interface NoteUpdate {
  content?: string | null;
  title?: string | null;
  tags?: string | null;
}

export interface VulnerabilityCreate {
  binary_name: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  function_name?: string | null;
  address?: string | number | null;
  evidence?: string | null;
  cvss?: number | null;
  exploitability?: string | null;
}

export interface AnalysisProgress {
  binary_name: string;
  total_notes: number;
  notes_by_type: Record<string, number>;
  findings_count: number;
  findings_by_severity: Record<string, number>;
}

export const projectApi = {
  getOverview: () => apiClient.get<ProjectOverview>('/project').then(res => res.data),
  getMcpTools: () => apiClient.get<McpTool[]>('/mcp/tools').then(res => res.data),
  listBinaries: (offset = 0, limit = 50) => 
    apiClient.get<BinarySummary[]>('/project/binaries', { params: { offset, limit } }).then(res => res.data),
  searchExports: (functionName: string, match = 'exact', offset = 0, limit = 50) =>
    apiClient.get<{ binary: string; export: BinaryExport }[]>('/project/search/exports', { params: { function_name: functionName, match, offset, limit } }).then(res => res.data),
  searchFunctions: (functionName: string, match = 'contains', offset = 0, limit = 50) =>
    apiClient.get<{ binary: string; function: BinaryFunction }[]>('/project/search/functions', { params: { function_name: functionName, match, offset, limit } }).then(res => res.data),
  searchStrings: (query: string, match = 'contains', offset = 0, limit = 50) =>
    apiClient.get<{ binary: string; string: string; address: string }[]>('/project/search/strings', { params: { query, match, offset, limit } }).then(res => res.data),
};

export const binaryApi = {
  getMetadata: (binaryName: string) => apiClient.get<BinaryMetadata>(`/binary/${binaryName}`).then(res => res.data),
  getFunctions: (binaryName: string, query?: string, offset = 0, limit = 50) =>
    apiClient.get<BinaryFunction[]>(`/binary/${binaryName}/functions`, { params: { query, offset, limit } }).then(res => res.data),
  getDisassembly: (binaryName: string, startAddress: string, endAddress: string) =>
    apiClient.get<string>(`/binary/${binaryName}/disassembly`, { params: { start_address: startAddress, end_address: endAddress } }).then(res => res.data),
  getFunctionDisassembly: (binaryName: string, address: string) =>
    apiClient.get<string>(`/binary/${binaryName}/function/${address}/disassembly`).then(res => res.data),
  getFunctionPseudocode: (binaryName: string, address: string) =>
    apiClient.get<PseudocodeResult>(`/binary/${binaryName}/function/${address}/pseudocode`).then(res => res.data),
  getStrings: (binaryName: string, query?: string, offset = 0, limit = 50) =>
    apiClient.get<BinaryString[]>(`/binary/${binaryName}/strings`, { params: { query, offset, limit } }).then(res => res.data),
  getImports: (binaryName: string, offset = 0, limit = 50) =>
    apiClient.get<BinaryImport[]>(`/binary/${binaryName}/imports`, { params: { offset, limit } }).then(res => res.data),
  getExports: (binaryName: string, query?: string, offset = 0, limit = 50) =>
    apiClient.get<BinaryExport[]>(`/binary/${binaryName}/exports`, { params: { query, offset, limit } }).then(res => res.data),
  getSymbols: (binaryName: string, query?: string, offset = 0, limit = 50) =>
    apiClient.get<BinarySymbol[]>(`/binary/${binaryName}/symbols`, { params: { query, offset, limit } }).then(res => res.data),
  getSegments: (binaryName: string) => apiClient.get<BinarySegment[]>(`/binary/${binaryName}/segments`).then(res => res.data),
  resolveAddress: (binaryName: string, address: string) =>
    apiClient.get<ResolveAddressResult>(`/binary/${binaryName}/address/${address}`).then(res => res.data),
  getCallers: (binaryName: string, address: string, depth = 1, limit = 50) =>
    apiClient.get<PaginatedResponse<FunctionCallerRef>>(`/binary/${binaryName}/function/${address}/callers`, { params: { depth, limit } }).then(res => res.data),
  getCallees: (binaryName: string, address: string, depth = 1, limit = 50) =>
    apiClient.get<PaginatedResponse<FunctionCalleeRef>>(`/binary/${binaryName}/function/${address}/callees`, { params: { depth, limit } }).then(res => res.data),
  getXrefsTo: (binaryName: string, address: string, offset = 0, limit = 50) =>
    apiClient.get<XrefToItem[]>(`/binary/${binaryName}/xrefs/to/${address}`, { params: { offset, limit } }).then(res => res.data),
  getXrefsFrom: (binaryName: string, address: string, offset = 0, limit = 50) =>
    apiClient.get<XrefFromItem[]>(`/binary/${binaryName}/xrefs/from/${address}`, { params: { offset, limit } }).then(res => res.data),

  // Methods used by components (aliases or new)
  getDisassemblyContext: (binaryName: string, address: string, contextLines = 10) =>
    apiClient.get<{ lines: string[] }>(`/binary/${binaryName}/address/${address}/disassembly`, { params: { context_lines: contextLines } }).then(res => res.data),
  
  listFunctions: (binaryName: string, query?: string, offset = 0, limit = 50) =>
    binaryApi.getFunctions(binaryName, query, offset, limit),
  
  listStrings: (binaryName: string, query?: string, _minLength?: number, offset = 0, limit = 50) =>
    // Note: minLength is not currently supported by backend
    binaryApi.getStrings(binaryName, query, offset, limit),
    
  getFunctionCallers: (binaryName: string, address: string) => binaryApi.getCallers(binaryName, address),
  getFunctionCallees: (binaryName: string, address: string) => binaryApi.getCallees(binaryName, address),

  listImports: (binaryName: string, offset = 0, limit = 50) =>
    binaryApi.getImports(binaryName, offset, limit),
    
  listExports: (binaryName: string, query?: string, offset = 0, limit = 50) =>
    binaryApi.getExports(binaryName, query, offset, limit),
    
  listSymbols: (binaryName: string, query?: string, offset = 0, limit = 50) =>
    binaryApi.getSymbols(binaryName, query, offset, limit),
    
  listSegments: (binaryName: string) =>
    binaryApi.getSegments(binaryName),

  executeDSL: (binaryName: string, script: string) =>
    apiClient.post<any>(`/binary/${binaryName}/dsl/execute`, { script }).then(res => res.data),
};

export const notesApi = {
  getNotes: (params: { binary_name?: string; query?: string; note_type?: string; tags?: string; limit?: number }) =>
    apiClient.get<Note[]>('/notes', { params }).then(res => res.data),
  createNote: (data: NoteCreate) =>
    apiClient.post<{ note_id: number }>('/notes', data).then(res => res.data),
  updateNote: (noteId: number, data: NoteUpdate) =>
    apiClient.put<{ success: boolean }>(`/notes/${noteId}`, data).then(res => res.data),
  deleteNote: (noteId: number) =>
    apiClient.delete<{ success: boolean }>(`/notes/${noteId}`).then(res => res.data),
  
  getVulnerabilities: (params: { binary_name?: string; severity?: string; category?: string }) =>
    apiClient.get<Vulnerability[]>('/vulnerabilities', { params }).then(res => res.data),
  reportVulnerability: (data: VulnerabilityCreate) =>
    apiClient.post<{ id: number; note_id: number }>('/vulnerabilities', data).then(res => res.data),
    
  getAnalysisProgress: (binaryName: string) =>
    apiClient.get<AnalysisProgress>(`/binary/${binaryName}/analysis-progress`).then(res => res.data),
};
