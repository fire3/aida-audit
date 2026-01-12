import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { binaryApi } from '../api/client';
import { Search, Layers, FileDigit } from 'lucide-react';
import { Input } from '../components/ui/input';
import { cn } from '../lib/utils';

export function SegmentsBrowser() {
  const { binaryName } = useParams<{ binaryName: string }>();
  const [searchTerm, setSearchTerm] = useState('');

  const { data: segments, isLoading } = useQuery({
    queryKey: ['segments', binaryName],
    queryFn: () => binaryApi.listSegments(binaryName!),
    enabled: !!binaryName,
  });

  const filteredSegments = segments?.filter(seg => 
    seg.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    seg.type.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="h-full flex flex-col bg-background">
      {/* Header */}
      <div className="flex-none p-4 border-b border-border bg-card/50">
        <div className="flex items-center gap-4 max-w-4xl mx-auto w-full">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search segments..."
              className="pl-9 bg-background/80"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <div className="text-sm text-muted-foreground font-mono">
            {segments?.length || 0} segments
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-4">
        <div className="max-w-4xl mx-auto w-full">
          {isLoading ? (
            <div className="space-y-4">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="h-16 bg-muted/50 rounded-lg animate-pulse" />
              ))}
            </div>
          ) : (
            <div className="grid gap-4">
              {filteredSegments?.map((seg) => (
                <div
                  key={seg.name}
                  className="bg-card border border-border rounded-lg p-4 hover:border-primary/50 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className={cn(
                        "p-2 rounded-md",
                        seg.permissions.includes('x') ? "bg-red-500/10 text-red-500" :
                        seg.permissions.includes('w') ? "bg-yellow-500/10 text-yellow-500" :
                        "bg-blue-500/10 text-blue-500"
                      )}>
                        <Layers className="h-5 w-5" />
                      </div>
                      <div>
                        <h3 className="font-semibold text-lg flex items-center gap-2">
                          {seg.name}
                          <span className="text-xs px-2 py-0.5 rounded-full bg-muted text-muted-foreground font-normal">
                            {seg.type}
                          </span>
                        </h3>
                        <div className="flex items-center gap-4 mt-1 text-sm text-muted-foreground font-mono">
                          <span title="Start Address">{seg.start_address}</span>
                          <span>-</span>
                          <span title="End Address">{seg.end_address}</span>
                          <span className="text-xs px-1.5 py-0.5 rounded bg-muted/50 text-foreground/70">
                            {seg.size.toLocaleString()} bytes
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-col items-end gap-2">
                      <div className="flex items-center gap-1 font-mono text-sm">
                        <span className={cn(
                          "px-1.5 py-0.5 rounded text-xs uppercase border",
                          seg.permissions.includes('r') 
                            ? "bg-green-500/10 text-green-600 border-green-500/20" 
                            : "bg-muted text-muted-foreground border-transparent opacity-50"
                        )}>R</span>
                        <span className={cn(
                          "px-1.5 py-0.5 rounded text-xs uppercase border",
                          seg.permissions.includes('w') 
                            ? "bg-yellow-500/10 text-yellow-600 border-yellow-500/20" 
                            : "bg-muted text-muted-foreground border-transparent opacity-50"
                        )}>W</span>
                        <span className={cn(
                          "px-1.5 py-0.5 rounded text-xs uppercase border",
                          seg.permissions.includes('x') 
                            ? "bg-red-500/10 text-red-600 border-red-500/20" 
                            : "bg-muted text-muted-foreground border-transparent opacity-50"
                        )}>X</span>
                      </div>
                      
                      {seg.file_offset !== null && (
                        <div className="flex items-center gap-1.5 text-xs text-muted-foreground" title="File Offset">
                          <FileDigit className="h-3.5 w-3.5" />
                          <span className="font-mono">0x{seg.file_offset.toString(16)}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
              
              {filteredSegments?.length === 0 && (
                <div className="text-center py-12 text-muted-foreground">
                  No segments found matching "{searchTerm}"
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
