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
  call_site_address: string;
  caller_address: string;
  caller_name?: string | null;
}

export interface FunctionCalleeRef {
  call_site_address: string;
  callee_address: string;
  callee_name?: string | null;
  call_type?: string | null;
}

export interface PseudocodeResult {
  function_address: string;
  name: string;
  pseudocode: string;
}

// Audit Interfaces

export interface AuditPlan {
  id: number;
  title: string;
  description: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  created_at: number;
  updated_at: number;
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
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: number;
}

export interface AuditMemory {
  key: string;
  value: any;
  updated_at: number;
}

export const auditApi = {
  getPlans: async (status?: string) => {
    const params = status ? { status } : {};
    const res = await apiClient.get<AuditPlan[]>('/audit/plans', { params });
    return res.data;
  },
  getLogs: async (limit: number = 50) => {
    const res = await apiClient.get<AuditLog[]>('/audit/logs', { params: { limit } });
    return res.data;
  },
  getMemory: async () => {
    const res = await apiClient.get<Record<string, any>>('/audit/memory');
    return res.data;
  },
  getMessages: async (sessionId?: string, limit: number = 100) => {
    const params: any = { limit };
    if (sessionId) params.session_id = sessionId;
    const res = await apiClient.get<AuditMessage[]>('/audit/messages', { params });
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

export interface Note {
  note_id: number;
  binary_name: string;
  function_name?: string | null;
  address?: number | null;
  note_type: string;
  content: string;
  confidence: string;
  tags?: string[] | null;
  created_at: string;
  updated_at: string;
}

export interface NoteCreate {
  binary_name: string;
  content: string;
  note_type: string;
  function_name?: string | null;
  address?: string | number | null;
  tags?: string | null;
  confidence?: string;
}

export interface NoteUpdate {
  content?: string | null;
  tags?: string | null;
}

export interface Finding {
  finding_id: number;
  note_id: number;
  binary_name: string;
  function_name?: string | null;
  address?: number | null;
  severity: string;
  category: string;
  description: string;
  evidence?: string | null;
  cvss?: number | null;
  exploitability?: string | null;
  created_at: string;
}

export interface FindingCreate {
  binary_name: string;
  severity: string;
  category: string;
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
    apiClient.get<FunctionCallerRef[]>(`/binary/${binaryName}/function/${address}/callers`, { params: { depth, limit } }).then(res => res.data),
  getCallees: (binaryName: string, address: string, depth = 1, limit = 50) =>
    apiClient.get<FunctionCalleeRef[]>(`/binary/${binaryName}/function/${address}/callees`, { params: { depth, limit } }).then(res => res.data),
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
  
  getFindings: (params: { binary_name?: string; severity?: string; category?: string }) =>
    apiClient.get<Finding[]>('/findings', { params }).then(res => res.data),
  markFinding: (data: FindingCreate) =>
    apiClient.post<{ finding_id: number; note_id: number }>('/findings', data).then(res => res.data),
    
  getAnalysisProgress: (binaryName: string) =>
    apiClient.get<AnalysisProgress>(`/binary/${binaryName}/analysis-progress`).then(res => res.data),
};
