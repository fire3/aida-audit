import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { binaryApi, projectApi } from '../api/client';
import type { FunctionCallerRef, FunctionCalleeRef } from '../api/client';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Code, FileText, ArrowRight, ArrowLeft, Search, Database } from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface FunctionDetailProps {
  binaryName: string;
  address: string;
  onNavigate?: (address: string) => void;
}

export function FunctionDetail({ binaryName, address, onNavigate }: FunctionDetailProps) {
  const [view, setView] = useState<'pseudocode' | 'disassembly' | 'implementation'>('pseudocode');
  const [callerSearch, setCallerSearch] = useState('');
  const [calleeSearch, setCalleeSearch] = useState('');

  const { data: addressInfo } = useQuery({
    queryKey: ['addressInfo', binaryName, address],
    queryFn: () => binaryApi.resolveAddress(binaryName, address),
  });

  const functionInfo = addressInfo?.function;
  const isThunk = functionInfo?.is_thunk;

  const { data: pseudocode, isLoading: isPseudoLoading } = useQuery({
    queryKey: ['pseudocode', binaryName, address],
    queryFn: () => binaryApi.getFunctionPseudocode(binaryName, address),
    enabled: view === 'pseudocode',
  });

  const { data: implementation, isLoading: isImplLoading } = useQuery({
    queryKey: ['implementation', functionInfo?.name],
    queryFn: async () => {
      if (!functionInfo?.name) return null;
      const results = await projectApi.searchExports(functionInfo.name);
      // Filter out the current binary if possible, or just take the first one that is likely the library
      // Usually thunk in binary A points to export in binary B.
      const target = results.find(r => r.binary !== binaryName);
      if (!target) return null;
      
      // Fetch pseudocode for the target implementation
      try {
        const pseudo = await binaryApi.getFunctionPseudocode(target.binary, target.export.address);
        return { ...target, pseudocode: pseudo?.pseudocode };
      } catch {
        return { ...target, pseudocode: null };
      }
    },
    enabled: view === 'implementation' && !!isThunk && !!functionInfo?.name,
  });

  const { data: disassembly, isLoading: isDisasmLoading } = useQuery({
    queryKey: ['disassembly', binaryName, address],
    queryFn: () => binaryApi.getFunctionDisassembly(binaryName, address),
    enabled: view === 'disassembly',
  });

  const { data: callers, isLoading: isCallersLoading } = useQuery({
    queryKey: ['callers', binaryName, address],
    queryFn: () => binaryApi.getFunctionCallers(binaryName, address),
  });

  const { data: callees, isLoading: isCalleesLoading } = useQuery({
    queryKey: ['callees', binaryName, address],
    queryFn: () => binaryApi.getFunctionCallees(binaryName, address),
  });

  const filteredCallers = callers?.filter((ref: FunctionCallerRef) => 
    (ref.caller_name?.toLowerCase().includes(callerSearch.toLowerCase()) || 
     ref.caller_address.toLowerCase().includes(callerSearch.toLowerCase()))
  );

  const filteredCallees = callees?.filter((ref: FunctionCalleeRef) => 
    (ref.callee_name?.toLowerCase().includes(calleeSearch.toLowerCase()) || 
     ref.callee_address.toLowerCase().includes(calleeSearch.toLowerCase()))
  );

  return (
    <div className="flex h-full bg-background overflow-hidden">
      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 border-r border-border">
        {/* Toolbar */}
        <div className="border-b border-border p-2 flex space-x-2 bg-muted/20">
          <Button
            variant={view === 'pseudocode' ? 'secondary' : 'ghost'}
            size="sm"
            onClick={() => setView('pseudocode')}
          >
            <Code className="mr-2 h-4 w-4" />
            Pseudocode
          </Button>
          <Button
            variant={view === 'disassembly' ? 'secondary' : 'ghost'}
            size="sm"
            onClick={() => setView('disassembly')}
          >
            <FileText className="mr-2 h-4 w-4" />
            Disassembly
          </Button>
          {isThunk && (
            <Button
              variant={view === 'implementation' ? 'secondary' : 'ghost'}
              size="sm"
              onClick={() => setView('implementation')}
            >
              <Database className="mr-2 h-4 w-4" />
              Implementation
            </Button>
          )}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto">
          {view === 'pseudocode' && (
            isPseudoLoading ? (
              <div className="flex items-center justify-center h-full text-muted-foreground">Loading pseudocode...</div>
            ) : (
              <div className="h-full text-sm">
                <SyntaxHighlighter
                  language="cpp"
                  style={vscDarkPlus}
                  customStyle={{ margin: 0, height: '100%', borderRadius: 0 }}
                  showLineNumbers
                >
                  {pseudocode?.pseudocode || "// No pseudocode available."}
                </SyntaxHighlighter>
              </div>
            )
          )}

          {view === 'disassembly' && (
            isDisasmLoading ? (
              <div className="flex items-center justify-center h-full text-muted-foreground">Loading disassembly...</div>
            ) : (
              <div className="h-full text-sm">
                <SyntaxHighlighter
                  language="nasm"
                  style={vscDarkPlus}
                  customStyle={{ margin: 0, height: '100%', borderRadius: 0 }}
                  showLineNumbers
                >
                  {disassembly || "; No disassembly available."}
                </SyntaxHighlighter>
              </div>
            )
          )}

          {view === 'implementation' && (
            isImplLoading ? (
              <div className="flex items-center justify-center h-full text-muted-foreground">Searching implementation...</div>
            ) : implementation ? (
              <div className="flex flex-col h-full">
                <div className="p-4 border-b border-border bg-muted/10">
                  <div className="text-sm space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-muted-foreground">Binary:</span>
                      <span className="font-mono text-primary">{implementation.binary}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-muted-foreground">Address:</span>
                      <span className="font-mono">{implementation.export.address}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-muted-foreground">Name:</span>
                      <span className="font-mono">{implementation.export.name}</span>
                    </div>
                  </div>
                </div>
                <div className="flex-1 overflow-auto">
                  <SyntaxHighlighter
                    language="cpp"
                    style={vscDarkPlus}
                    customStyle={{ margin: 0, height: '100%', borderRadius: 0 }}
                    showLineNumbers
                  >
                    {implementation.pseudocode || "// No pseudocode available for implementation."}
                  </SyntaxHighlighter>
                </div>
              </div>
            ) : (
              <div className="flex items-center justify-center h-full text-muted-foreground">
                No implementation found in other binaries.
              </div>
            )
          )}
        </div>
      </div>

      {/* Xrefs Sidebar (Fixed Right) */}
      <div className="w-80 flex flex-col bg-background border-l border-border">
        {/* Callers */}
        <div className="flex-1 flex flex-col min-h-0 border-b border-border">
          <div className="p-3 border-b border-border font-semibold flex items-center bg-muted/30 text-sm">
            <ArrowLeft className="mr-2 h-4 w-4 text-blue-600 dark:text-blue-400" />
            Callers ({filteredCallers?.length || 0})
          </div>
          <div className="p-2 border-b border-border bg-background">
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-3 w-3 text-muted-foreground" />
              <Input
                placeholder="Search callers..."
                value={callerSearch}
                onChange={(e) => setCallerSearch(e.target.value)}
                className="h-8 pl-8 text-xs"
              />
            </div>
          </div>
          <div className="flex-1 overflow-auto p-0">
            {isCallersLoading ? (
              <div className="p-4 text-muted-foreground text-sm">Loading...</div>
            ) : (
              <div className="divide-y divide-border">
                {filteredCallers?.map((ref) => (
                  <div
                    key={`${ref.caller_address}-${ref.call_site_address}`}
                    className="p-2 hover:bg-muted/50 cursor-pointer transition-colors group"
                    onClick={() => onNavigate?.(ref.caller_address)}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="font-mono text-sm font-medium text-foreground truncate min-w-0 group-hover:text-blue-600 dark:group-hover:text-blue-400" title={ref.caller_name || ref.caller_address}>
                        {ref.caller_name || ref.caller_address}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono flex-shrink-0">
                        {ref.caller_address}
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground mt-0.5 font-mono">
                      callsite {ref.call_site_address}
                    </div>
                  </div>
                ))}
                {filteredCallers?.length === 0 && (
                  <div className="p-4 text-center text-muted-foreground text-xs">
                    {callerSearch ? 'No matching callers found.' : 'No callers found.'}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Callees */}
        <div className="flex-1 flex flex-col min-h-0">
          <div className="p-3 border-b border-border font-semibold flex items-center bg-muted/30 text-sm">
            <ArrowRight className="mr-2 h-4 w-4 text-green-600 dark:text-green-400" />
            Callees ({filteredCallees?.length || 0})
          </div>
          <div className="p-2 border-b border-border bg-background">
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-3 w-3 text-muted-foreground" />
              <Input
                placeholder="Search callees..."
                value={calleeSearch}
                onChange={(e) => setCalleeSearch(e.target.value)}
                className="h-8 pl-8 text-xs"
              />
            </div>
          </div>
          <div className="flex-1 overflow-auto p-0">
            {isCalleesLoading ? (
              <div className="p-4 text-muted-foreground text-sm">Loading...</div>
            ) : (
              <div className="divide-y divide-border">
                {filteredCallees?.map((ref) => (
                  <div
                    key={`${ref.callee_address}-${ref.call_site_address}`}
                    className="p-2 hover:bg-muted/50 cursor-pointer transition-colors group"
                    onClick={() => onNavigate?.(ref.callee_address)}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="font-mono text-sm font-medium text-foreground truncate min-w-0 group-hover:text-green-600 dark:group-hover:text-green-400" title={ref.callee_name || ref.callee_address}>
                        {ref.callee_name || ref.callee_address}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono flex-shrink-0">
                        {ref.callee_address}
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground mt-0.5 font-mono flex items-center justify-between">
                      <span>callsite {ref.call_site_address}</span>
                      {ref.call_type && <span className="text-[10px] px-1 rounded bg-muted text-muted-foreground">{ref.call_type}</span>}
                    </div>
                  </div>
                ))}
                {filteredCallees?.length === 0 && (
                  <div className="p-4 text-center text-muted-foreground text-xs">
                    {calleeSearch ? 'No matching callees found.' : 'No callees found.'}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
