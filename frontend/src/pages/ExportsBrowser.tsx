import { useState, useEffect } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { binaryApi } from '../api/client';
import type { BinaryExport, XrefToItem } from '../api/client';
import { Input } from '../components/ui/input';
import { Button } from '../components/ui/button';
import { Search, ChevronLeft, ChevronRight, ArrowRight, Share2 } from 'lucide-react';
import { cn, formatAddress } from '../lib/utils';
import { useDebounce } from '../hooks/useDebounce';
import { useTranslation } from 'react-i18next';

interface ExportDetailProps {
  binaryName: string;
  exportItem: BinaryExport;
  onNavigate?: (address: string) => void;
}

function ExportDetail({ binaryName, exportItem, onNavigate }: ExportDetailProps) {
  const { t } = useTranslation();
  const { data: xrefs, isLoading } = useQuery({
    queryKey: ['xrefs-to', binaryName, exportItem.address],
    queryFn: () => binaryApi.getXrefsTo(binaryName, exportItem.address),
  });

  return (
    <div className="h-full flex flex-col bg-background">
      <div className="p-4 border-b border-border bg-muted/20">
        <h2 className="text-lg font-semibold flex items-center">
          <Share2 className="mr-2 h-5 w-5 text-muted-foreground" />
          {t('exports_browser.title')}
        </h2>
        <div className="mt-2 grid grid-cols-2 gap-4">
          <div>
            <div className="text-xs font-mono text-muted-foreground">{t('common.name')}</div>
            <div className="font-medium">{exportItem.name}</div>
          </div>
          <div>
            <div className="text-xs font-mono text-muted-foreground">{t('common.address')}</div>
            <div className="font-mono text-sm">{formatAddress(exportItem.address)}</div>
          </div>
          <div>
            <div className="text-xs font-mono text-muted-foreground">{t('common.ordinal')}</div>
            <div className="font-mono text-sm">{exportItem.ordinal}</div>
          </div>
          {exportItem.forwarder && (
            <div>
              <div className="text-xs font-mono text-muted-foreground">{t('exports_browser.forwarder')}</div>
              <div className="font-mono text-sm">{exportItem.forwarder}</div>
            </div>
          )}
        </div>
      </div>

      <div className="flex-1 flex flex-col min-h-0">
        <div className="p-3 border-b border-border font-semibold flex items-center bg-muted/30 text-sm">
          <ArrowRight className="mr-2 h-4 w-4 text-green-600 dark:text-green-400" />
          {t('common.cross_references')} ({xrefs?.length || 0})
        </div>
        <div className="flex-1 overflow-auto p-0">
          {isLoading ? (
            <div className="p-4 text-muted-foreground text-sm">{t('common.loading_xrefs')}</div>
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
                    {ref.xref_type} {t('common.reference')}
                  </div>
                </div>
              ))}
              {xrefs?.length === 0 && (
                <div className="p-4 text-center text-muted-foreground text-xs">
                  {t('common.no_xrefs')}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function ExportsBrowser() {
  const { t } = useTranslation();
  const { binaryName } = useParams<{ binaryName: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const [selectedExport, setSelectedExport] = useState<BinaryExport | null>(null);
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

  const { data: exports, isLoading } = useQuery({
    queryKey: ['exports', binaryName, debouncedSearch, page],
    queryFn: () => binaryApi.listExports(binaryName!, debouncedSearch, page * limit, limit),
    enabled: !!binaryName,
  });

  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(e.target.value);
    setPage(0);
  };

  return (
    <div className="flex h-full">
      {/* Exports List */}
      <div className="w-[350px] border-r flex flex-col bg-background">
        <div className="p-4 border-b space-y-2">
          <div className="relative">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={t('common.search')}
              value={searchTerm}
              onChange={handleSearch}
              className="pl-8"
            />
          </div>
        </div>
        
        <div className="flex-1 overflow-auto">
          {isLoading ? (
            <div className="p-4 text-center text-muted-foreground">{t('common.loading')}</div>
          ) : (
            <div className="divide-y">
              {exports?.map((exp) => (
                <div
                  key={`${exp.name}-${exp.address}`}
                  className={cn(
                    "p-3 cursor-pointer hover:bg-muted/50 transition-colors text-sm",
                    selectedExport?.address === exp.address ? "bg-muted" : ""
                  )}
                  onClick={() => setSelectedExport(exp)}
                >
                  <div className="font-medium text-primary truncate" title={exp.name}>
                    {exp.name}
                  </div>
                  <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                    <span className="font-mono">{exp.address}</span>
                    <span className="font-mono">Ord: {exp.ordinal}</span>
                  </div>
                </div>
              ))}
              {exports?.length === 0 && (
                <div className="p-4 text-center text-muted-foreground">No exports found.</div>
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
            disabled={!exports || exports.length < limit}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Export Detail */}
      <div className="flex-1 flex flex-col overflow-hidden bg-slate-50 dark:bg-slate-950">
        {selectedExport ? (
          <ExportDetail 
            binaryName={binaryName!} 
            exportItem={selectedExport}
            onNavigate={(addr) => navigate(`/binary/${binaryName}/functions?address=${addr}`)}
          />
        ) : (
          <div className="flex-1 flex items-center justify-center text-muted-foreground">
            Select an export to view details and cross-references
          </div>
        )}
      </div>
    </div>
  );
}
