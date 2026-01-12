import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { binaryApi } from '../api/client';
import type { BinaryImport } from '../api/client';
import { Button } from '../components/ui/button';
import { ChevronLeft, ChevronRight, ArrowRight, Import } from 'lucide-react';
import { cn } from '../lib/utils';

interface ImportDetailProps {
  binaryName: string;
  importItem: BinaryImport;
  onNavigate?: (address: string) => void;
}

function ImportDetail({ binaryName, importItem, onNavigate }: ImportDetailProps) {
  const { data: xrefs, isLoading } = useQuery({
    queryKey: ['xrefs-to', binaryName, importItem.address],
    queryFn: () => binaryApi.getXrefsTo(binaryName, importItem.address),
  });

  return (
    <div className="h-full flex flex-col bg-background">
      <div className="p-4 border-b border-border bg-muted/20">
        <h2 className="text-lg font-semibold flex items-center">
          <Import className="mr-2 h-5 w-5 text-muted-foreground" />
          Import Details
        </h2>
        <div className="mt-2 grid grid-cols-2 gap-4">
          <div>
            <div className="text-xs font-mono text-muted-foreground">Library</div>
            <div className="font-medium">{importItem.library}</div>
          </div>
          <div>
            <div className="text-xs font-mono text-muted-foreground">Name</div>
            <div className="font-medium">{importItem.name}</div>
          </div>
          <div>
            <div className="text-xs font-mono text-muted-foreground">Address</div>
            <div className="font-mono text-sm">{importItem.address}</div>
          </div>
          <div>
            <div className="text-xs font-mono text-muted-foreground">Ordinal</div>
            <div className="font-mono text-sm">{importItem.ordinal}</div>
          </div>
          <div>
            <div className="text-xs font-mono text-muted-foreground">Thunk Address</div>
            <div className="font-mono text-sm">{importItem.thunk_address}</div>
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
              {xrefs?.map((ref: any, idx) => (
                <div
                  key={`${ref.from_address}-${idx}`}
                  className="p-3 hover:bg-muted/50 cursor-pointer transition-colors group"
                  onClick={() => onNavigate?.(ref.from_address)}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-mono text-sm font-medium text-foreground truncate min-w-0 group-hover:text-green-600 dark:group-hover:text-green-400">
                      {ref.from_function || ref.from_address}
                    </div>
                    <div className="text-xs text-muted-foreground font-mono flex-shrink-0">
                      {ref.from_address}
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

export function ImportsBrowser() {
  const { binaryName } = useParams<{ binaryName: string }>();
  const navigate = useNavigate();
  const [selectedImport, setSelectedImport] = useState<BinaryImport | null>(null);
  const [page, setPage] = useState(0);
  const limit = 50;

  const { data: imports, isLoading } = useQuery({
    queryKey: ['imports', binaryName, page],
    queryFn: () => binaryApi.listImports(binaryName!, page * limit, limit),
    enabled: !!binaryName,
  });

  return (
    <div className="flex h-full">
      {/* Imports List */}
      <div className="w-[350px] border-r flex flex-col bg-background">
        <div className="p-4 border-b space-y-2">
          <h2 className="text-lg font-semibold">Imports</h2>
        </div>
        
        <div className="flex-1 overflow-auto">
          {isLoading ? (
            <div className="p-4 text-center text-muted-foreground">Loading...</div>
          ) : (
            <div className="divide-y">
              {imports?.map((imp) => (
                <div
                  key={`${imp.library}-${imp.name}-${imp.address}`}
                  className={cn(
                    "p-3 cursor-pointer hover:bg-muted/50 transition-colors text-sm",
                    selectedImport?.address === imp.address ? "bg-muted" : ""
                  )}
                  onClick={() => setSelectedImport(imp)}
                >
                  <div className="font-medium text-primary truncate" title={imp.name}>
                    {imp.name}
                  </div>
                  <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                    <span className="font-mono truncate max-w-[120px]" title={imp.library}>{imp.library}</span>
                    <span className="font-mono">{imp.address}</span>
                  </div>
                </div>
              ))}
              {imports?.length === 0 && (
                <div className="p-4 text-center text-muted-foreground">No imports found.</div>
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
            disabled={!imports || imports.length < limit}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Import Detail */}
      <div className="flex-1 flex flex-col overflow-hidden bg-slate-50 dark:bg-slate-950">
        {selectedImport ? (
          <ImportDetail 
            binaryName={binaryName!} 
            importItem={selectedImport}
            onNavigate={(addr) => navigate(`/binary/${binaryName}/functions?address=${addr}`)}
          />
        ) : (
          <div className="flex-1 flex items-center justify-center text-muted-foreground">
            Select an import to view details and cross-references
          </div>
        )}
      </div>
    </div>
  );
}
