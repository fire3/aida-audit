import { useState, useEffect } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { binaryApi } from '../api/client';
import type { BinarySymbol, XrefToItem } from '../api/client';
import { Input } from '../components/ui/input';
import { Button } from '../components/ui/button';
import { Search, ChevronLeft, ChevronRight, ArrowRight, Database } from 'lucide-react';
import { cn, formatAddress } from '../lib/utils';
import { useDebounce } from '../hooks/useDebounce';

interface SymbolDetailProps {
  binaryName: string;
  symbolItem: BinarySymbol;
  onNavigate?: (address: string) => void;
}

function SymbolDetail({ binaryName, symbolItem, onNavigate }: SymbolDetailProps) {
  const { data: xrefs, isLoading } = useQuery({
    queryKey: ['xrefs-to', binaryName, symbolItem.address],
    queryFn: () => binaryApi.getXrefsTo(binaryName, symbolItem.address),
  });

  return (
    <div className="h-full flex flex-col bg-background">
      <div className="p-4 border-b border-border bg-muted/20">
        <h2 className="text-lg font-semibold flex items-center">
          <Database className="mr-2 h-5 w-5 text-muted-foreground" />
          Symbol Details
        </h2>
        <div className="mt-2 grid grid-cols-2 gap-4">
          <div className="col-span-2">
            <div className="text-xs font-mono text-muted-foreground">Name</div>
            <div className="font-medium break-all">{symbolItem.name}</div>
          </div>
          {symbolItem.demangled_name && symbolItem.demangled_name !== symbolItem.name && (
            <div className="col-span-2">
              <div className="text-xs font-mono text-muted-foreground">Demangled Name</div>
              <div className="font-medium break-all">{symbolItem.demangled_name}</div>
            </div>
          )}
          <div>
            <div className="text-xs font-mono text-muted-foreground">Address</div>
            <div className="font-mono text-sm">{formatAddress(symbolItem.address)}</div>
          </div>
          <div>
            <div className="text-xs font-mono text-muted-foreground">Kind</div>
            <div className="font-mono text-sm">{symbolItem.kind}</div>
          </div>
          <div>
            <div className="text-xs font-mono text-muted-foreground">Size</div>
            <div className="font-mono text-sm">{symbolItem.size}</div>
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
                <div
                  key={`${ref.from_address}-${idx}`}
                  className="p-3 hover:bg-muted/50 cursor-pointer transition-colors group"
                  onClick={() => onNavigate?.(ref.from_address)}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-mono text-sm font-medium text-foreground truncate min-w-0 group-hover:text-green-600 dark:group-hover:text-green-400">
                      {ref.from_function || formatAddress(ref.from_address)}
                    </div>
                    <div className="text-xs text-muted-foreground font-mono flex-shrink-0">
                      {formatAddress(ref.from_address)}
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1 font-mono">
                    {ref.xref_type} reference
                  </div>
                </div>
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

export function SymbolsBrowser() {
  const { binaryName } = useParams<{ binaryName: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const [selectedSymbol, setSelectedSymbol] = useState<BinarySymbol | null>(null);
  const [page, setPage] = useState(0);
  const limit = 50;

  const queryParam = searchParams.get('q') || '';
  const [searchTerm, setSearchTerm] = useState(queryParam);
  const debouncedSearch = useDebounce(searchTerm, 300);

  // Sync URL with debounced value
  useEffect(() => {
    if (debouncedSearch !== queryParam) {
      setSearchParams(prev => {
        const newParams = new URLSearchParams(prev);
        if (debouncedSearch) {
          newParams.set('q', debouncedSearch);
        } else {
          newParams.delete('q');
        }
        return newParams;
      });
    }
  }, [debouncedSearch, queryParam, setSearchParams]);

  const { data: symbols, isLoading } = useQuery({
    queryKey: ['symbols', binaryName, debouncedSearch, page],
    queryFn: () => binaryApi.listSymbols(binaryName!, debouncedSearch, page * limit, limit),
    enabled: !!binaryName,
  });

  return (
    <div className="h-full flex">
      {/* List View */}
      <div className="w-1/2 flex flex-col border-r border-border min-w-[350px]">
        <div className="p-4 border-b border-border space-y-4">
          <div className="flex items-center space-x-2">
            <div className="relative flex-1">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search symbols..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setPage(0);
                }}
                className="pl-8"
              />
            </div>
          </div>
        </div>

        <div className="flex-1 overflow-auto">
          {isLoading ? (
            <div className="p-4 text-muted-foreground">Loading symbols...</div>
          ) : (
            <div className="divide-y divide-border">
              {symbols?.map((sym) => (
                <div
                  key={`${sym.address}-${sym.name}`}
                  className={cn(
                    "p-3 hover:bg-muted/50 cursor-pointer transition-colors",
                    selectedSymbol?.address === sym.address ? "bg-muted" : ""
                  )}
                  onClick={() => setSelectedSymbol(sym)}
                >
                  <div className="flex justify-between items-start">
                    <div className="font-medium text-sm truncate pr-2" title={sym.demangled_name || sym.name}>
                      {sym.name}
                    </div>
                    <div className="text-xs text-muted-foreground font-mono flex-shrink-0 bg-muted px-1.5 py-0.5 rounded">
                      {sym.kind}
                    </div>
                  </div>
                  <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                    <span className="font-mono">{formatAddress(sym.address)}</span>
                    <span className="font-mono">{sym.size} bytes</span>
                  </div>
                </div>
              ))}
              {symbols?.length === 0 && (
                <div className="p-4 text-center text-muted-foreground">No symbols found.</div>
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
            disabled={!symbols || symbols.length < limit}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Symbol Detail */}
      <div className="flex-1 flex flex-col overflow-hidden bg-slate-50 dark:bg-slate-950">
        {selectedSymbol ? (
          <SymbolDetail 
            binaryName={binaryName!} 
            symbolItem={selectedSymbol}
            onNavigate={(addr) => navigate(`/binary/${binaryName}/functions?address=${addr}`)}
          />
        ) : (
          <div className="flex-1 flex items-center justify-center text-muted-foreground">
            Select a symbol to view details and cross-references
          </div>
        )}
      </div>
    </div>
  );
}
