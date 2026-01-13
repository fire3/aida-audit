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
  pseudo_code: string;
}

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
  symbol?: any;
  segment?: any;
  section?: any;
  string_ref?: any;
  data_item?: any;
  is_code: boolean;
  is_data: boolean;
}

export interface McpTool {
  name: string;
  description: string;
  inputSchema: {
    type: string;
    properties: Record<string, any>;
    required?: string[];
  };
}

export const projectApi = {
  getOverview: () => apiClient.get<ProjectOverview>('/project').then(res => res.data),
  getMcpTools: () => apiClient.get<McpTool[]>('/mcp/tools').then(res => res.data),
  listBinaries: (offset = 0, limit = 50) => 
    apiClient.get<BinarySummary[]>('/project/binaries', { params: { offset, limit } }).then(res => res.data),
  searchExports: (functionName: string, match = 'exact', offset = 0, limit = 50) =>
    apiClient.get<{ binary: string; export: any }[]>('/project/search/exports', { params: { function_name: functionName, match, offset, limit } }).then(res => res.data),
  searchFunctions: (functionName: string, match = 'contains', offset = 0, limit = 50) =>
    apiClient.get<{ binary: string; function: BinaryFunction }[]>('/project/search/functions', { params: { function_name: functionName, match, offset, limit } }).then(res => res.data),
  searchStrings: (query: string, match = 'contains', offset = 0, limit = 50) =>
    apiClient.get<{ binary: string; string: string; address: string }[]>('/project/search/strings', { params: { query, match, offset, limit } }).then(res => res.data),
};

export const binaryApi = {
  getMetadata: (name: string) => apiClient.get<BinaryMetadata>(`/binary/${name}`).then(res => res.data),
  
  listFunctions: (name: string, query?: string, offset = 0, limit = 50) => 
    apiClient.get<BinaryFunction[]>(`/binary/${name}/functions`, { params: { query, offset, limit } }).then(res => res.data),
    
  getFunctionPseudocode: (name: string, address: string) =>
    apiClient.get<PseudocodeResult>(`/binary/${name}/function/${encodeURIComponent(address)}/pseudocode`).then(res => res.data),
    
  getFunctionDisassembly: (name: string, address: string) =>
    apiClient.get<string>(`/binary/${name}/function/${encodeURIComponent(address)}/disassembly`).then(res => res.data),

  getDisassemblyContext: (name: string, address: string, contextLines: number = 10) =>
    apiClient.get<string>(`/binary/${name}/address/${encodeURIComponent(address)}/disassembly`, { params: { context_lines: contextLines } }).then(res => res.data),

  getFunctionCallers: (name: string, address: string, depth?: number, limit?: number) =>
    apiClient.get<FunctionCallerRef[]>(`/binary/${name}/function/${encodeURIComponent(address)}/callers`, { params: { depth, limit } }).then(res => res.data),

  getFunctionCallees: (name: string, address: string, depth?: number, limit?: number) =>
    apiClient.get<FunctionCalleeRef[]>(`/binary/${name}/function/${encodeURIComponent(address)}/callees`, { params: { depth, limit } }).then(res => res.data),
    
  getXrefsTo: (name: string, address: string, offset = 0, limit = 50) =>
    apiClient.get<unknown[]>(`/binary/${name}/xrefs/to/${encodeURIComponent(address)}`, { params: { offset, limit } }).then(res => res.data),

  getXrefsFrom: (name: string, address: string, offset = 0, limit = 50) =>
    apiClient.get<unknown[]>(`/binary/${name}/xrefs/from/${encodeURIComponent(address)}`, { params: { offset, limit } }).then(res => res.data),

  listStrings: (name: string, query?: string, min_length?: number, offset = 0, limit = 50) =>
    apiClient.get<BinaryString[]>(`/binary/${name}/strings`, { params: { query, min_length, offset, limit } }).then(res => res.data),

  listImports: (name: string, offset = 0, limit = 50) =>
    apiClient.get<BinaryImport[]>(`/binary/${name}/imports`, { params: { offset, limit } }).then(res => res.data),

  listExports: (name: string, query?: string, offset = 0, limit = 50) =>
    apiClient.get<BinaryExport[]>(`/binary/${name}/exports`, { params: { query, offset, limit } }).then(res => res.data),

  listSymbols: (name: string, query?: string, offset = 0, limit = 50) =>
    apiClient.get<BinarySymbol[]>(`/binary/${name}/symbols`, { params: { query, offset, limit } }).then(res => res.data),

  listSegments: (name: string) =>
    apiClient.get<BinarySegment[]>(`/binary/${name}/segments`).then(res => res.data),

  resolveAddress: (name: string, address: string) =>
    apiClient.get<ResolveAddressResult>(`/binary/${name}/address/${encodeURIComponent(address)}`).then(res => res.data),
};
