import { useState, useMemo } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { binaryApi } from '../api/client';
import type { XrefToItem } from '../api/client';
import { Input } from '../components/ui/input';
import { Button } from '../components/ui/button';
import { Search, ChevronLeft, ChevronRight, Quote, ArrowRight, Filter, FileCode } from 'lucide-react';
import { cn, formatAddress } from '../lib/utils';

interface XrefItemProps {
  binaryName: string;
  xref: XrefToItem;
  onNavigate?: (address: string) => void;
}

function XrefItem({ binaryName, xref, onNavigate }: XrefItemProps) {
  const { data: disassembly, isLoading } = useQuery({
    queryKey: ['disassembly', binaryName, xref.from_address],
    queryFn: async () => {
      try {
        // Use new context-aware API with small context (3 lines)
        return await binaryApi.getDisassemblyContext(binaryName, xref.from_address, 3);
      } catch {
        return null;
      }
    },
    retry: false,
    staleTime: 1000 * 60 * 5,
  });

  const contextLines = useMemo(() => {
    if (!disassembly) return null;
    
    // disassembly is already { lines: string[] } from getDisassemblyContext
    const lines = disassembly.lines;
    const targetAddr = xref.from_address.toLowerCase();
    
    // Find line starting with address (ignoring case)
    const index = lines.findIndex(line => 
      line.trim().toLowerCase().startsWith(targetAddr)
    );

    // If we can't find the exact line, just show all lines (the backend already filtered them)
    // But we want to know which one to highlight
    
    return {
      lines: lines,
      targetIndex: index
    };
  }, [disassembly, xref.from_address]);

  return (
    <div className="p-3 hover:bg-muted/50 transition-colors group border-b border-border/50 last:border-0">
      <div 
        className={cn(
          "flex items-center justify-between gap-2 mb-2",
          xref.from_function ? "cursor-pointer" : ""
        )}
        onClick={() => xref.from_function && onNavigate?.(xref.from_function)}
      >
        <div className="flex items-center gap-2 min-w-0">
          <FileCode className="h-4 w-4 text-muted-foreground" />
          <div className={cn(
            "font-mono text-sm font-medium text-foreground truncate transition-colors",
            xref.from_function ? "group-hover:text-primary" : ""
          )}>
            {xref.from_function_name || formatAddress(xref.from_function) || (
              <span className="text-muted-foreground italic text-xs">No function</span>
            )}
          </div>
        </div>
        <div className="text-xs text-muted-foreground font-mono flex-shrink-0 bg-muted px-1.5 py-0.5 rounded">
          {formatAddress(xref.from_address)}
        </div>
      </div>
      
      {isLoading ? (
        <div className="ml-6 h-16 bg-muted/30 rounded animate-pulse" />
      ) : contextLines ? (
        <div className="ml-6 bg-muted/30 rounded border border-border/50 p-2 overflow-x-auto">
          <div className="font-mono text-xs space-y-0.5">
            {contextLines.lines.map((line: string, i: number) => (
              <div 
                key={i} 
                className={cn(
                  "whitespace-pre px-1 rounded",
                  i === contextLines.targetIndex 
                    ? "bg-yellow-500/15 text-yellow-700 dark:text-yellow-400 font-medium border border-yellow-500/20" 
                    : "text-muted-foreground/80"
                )}
              >
                {line}
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="ml-6 text-xs text-muted-foreground italic">
          {disassembly === null ? "No disassembly available (data reference?)" : "Address not found in disassembly"}
        </div>
      )}
      
      <div className="ml-6 mt-1 text-xs text-muted-foreground font-mono">
        Type: {xref.xref_type}
      </div>
    </div>
  );
}

interface StringDetailProps {
  binaryName: string;
  address: string;
  stringContent: string;
  onNavigate?: (address: string) => void;
}

function StringDetail({ binaryName, address, stringContent, onNavigate }: StringDetailProps) {
  const { data: xrefs, isLoading } = useQuery({
    queryKey: ['xrefs-to', binaryName, address],
    queryFn: () => binaryApi.getXrefsTo(binaryName, address),
  });

  return (
    <div className="h-full flex flex-col bg-background">
      <div className="p-4 border-b border-border bg-muted/20">
        <h2 className="text-lg font-semibold flex items-center">
          <Quote className="mr-2 h-5 w-5 text-muted-foreground" />
          String Details
        </h2>
        <div className="mt-2 space-y-1">
          <div className="text-sm font-mono text-muted-foreground">Address: {formatAddress(address)}</div>
          <div className="p-2 bg-muted rounded border border-border font-mono text-sm whitespace-pre-wrap break-all">
            {stringContent}
          </div>
        </div>
      </div>

      <div className="flex-1 flex flex-col min-h-0">
        <div className="p-3 border-b border-border font-semibold flex items-center bg-muted/30 text-sm">
          <ArrowRight className="mr-2 h-4 w-4 text-green-600 dark:text-green-400" />
          Cross References ({xrefs?.length || 0})
        </div>
        <div className="flex-1 overflow-auto p-0">
          {isLoading ? (
            <div className="p-4 text-muted-foreground text-sm">Loading xrefs...</div>
          ) : (
            <div className="divide-y divide-border">
              {xrefs?.map((ref: XrefToItem, idx) => (
                <XrefItem 
                  key={`${ref.from_address}-${idx}`}
                  binaryName={binaryName}
                  xref={ref}
                  onNavigate={onNavigate}
                />
              ))}
              {xrefs?.length === 0 && (
                <div className="p-4 text-center text-muted-foreground text-xs">
                  No cross references found.
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function StringsBrowser() {
  const { binaryName } = useParams<{ binaryName: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const [selectedString, setSelectedString] = useState<{ address: string; string: string } | null>(null);
  const [page, setPage] = useState(0);
  const [minLength, setMinLength] = useState<number | undefined>(undefined);
  const limit = 50;

  const query = searchParams.get('q') || '';

  const { data: strings, isLoading } = useQuery({
    queryKey: ['strings', binaryName, query, minLength, page],
    queryFn: () => binaryApi.listStrings(binaryName!, query, minLength, page * limit, limit),
    enabled: !!binaryName,
  });

  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchParams({ q: e.target.value });
    setPage(0);
  };

  const handleMinLengthChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = parseInt(e.target.value);
    setMinLength(isNaN(val) ? undefined : val);
    setPage(0);
  };

  return (
    <div className="flex h-full">
      {/* Strings List */}
      <div className="w-[350px] border-r flex flex-col bg-background">
        <div className="p-4 border-b space-y-2">
          <div className="relative">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search strings..."
              value={query}
              onChange={handleSearch}
              className="pl-8"
            />
          </div>
          <div className="relative flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <Input
              type="number"
              placeholder="Min length"
              value={minLength || ''}
              onChange={handleMinLengthChange}
              className="h-8 text-xs"
            />
          </div>
        </div>
        
        <div className="flex-1 overflow-auto">
          {isLoading ? (
            <div className="p-4 text-center text-muted-foreground">Loading...</div>
          ) : (
            <div className="divide-y">
              {strings?.map((str) => (
                <div
                  key={str.address}
                  className={cn(
                    "p-3 cursor-pointer hover:bg-muted/50 transition-colors text-sm",
                    selectedString?.address === str.address ? "bg-muted" : ""
                  )}
                  onClick={() => setSelectedString({ address: str.address, string: str.string })}
                >
                  <div className="font-mono font-medium text-primary truncate" title={str.string}>
                    {str.string}
                  </div>
                  <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                    <span className="font-mono">{formatAddress(str.address)}</span>
                    <span>{str.length} chars</span>
                    {str.section && <span>{str.section}</span>}
                  </div>
                </div>
              ))}
              {strings?.length === 0 && (
                <div className="p-4 text-center text-muted-foreground">No strings found.</div>
              )}
            </div>
          )}
        </div>

        <div className="p-2 border-t flex justify-between items-center bg-muted/10">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <span className="text-xs text-muted-foreground">Page {page + 1}</span>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setPage((p) => p + 1)}
            disabled={!strings || strings.length < limit}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* String Detail */}
      <div className="flex-1 flex flex-col overflow-hidden bg-slate-50 dark:bg-slate-950">
        {selectedString ? (
          <StringDetail 
            binaryName={binaryName!} 
            address={selectedString.address} 
            stringContent={selectedString.string}
            onNavigate={(addr) => navigate(`/binary/${binaryName}/functions?address=${addr}`)}
          />
        ) : (
          <div className="flex-1 flex items-center justify-center text-muted-foreground">
            Select a string to view details and cross-references
          </div>
        )}
      </div>
    </div>
  );
}
