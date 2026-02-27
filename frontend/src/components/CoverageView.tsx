import { useState, useEffect, useMemo } from 'react';
import { auditApi } from '../api/client';
import { useQuery } from '@tanstack/react-query';
import { Layers, Code2, FileCode, MoreHorizontal, Search } from 'lucide-react';

interface CoverageFunction {
  address: string;
  target_value: string;
  has_disasm: boolean;
  has_pseudocode: boolean;
  has_other: boolean;
  coverage_status: string;
}

interface CoverageData {
  binary_name: string;
  total_functions: number;
  coverage: {
    disasm_only: number;
    pseudocode_only: number;
    both: number;
    full: number;
    partial: number;
    none: number;
  };
  functions: CoverageFunction[];
}

const STATUS_COLORS: Record<string, { bg: string; border: string; text: string; label: string }> = {
  disasm_only: { bg: 'bg-blue-500', border: 'border-blue-600', text: 'text-blue-600', label: 'Disasm Only' },
  pseudocode_only: { bg: 'bg-emerald-500', border: 'border-emerald-600', text: 'text-emerald-600', label: 'Pseudocode Only' },
  both: { bg: 'bg-amber-500', border: 'border-amber-600', text: 'text-amber-600', label: 'Both' },
  full: { bg: 'bg-orange-500', border: 'border-orange-600', text: 'text-orange-600', label: 'Full' },
  partial: { bg: 'bg-purple-500', border: 'border-purple-600', text: 'text-purple-600', label: 'Partial' },
  none: { bg: 'bg-slate-300 dark:bg-slate-700', border: 'border-slate-400 dark:border-slate-600', text: 'text-slate-500', label: 'Not Viewed' },
};

const STATUS_ORDER = ['full', 'both', 'disasm_only', 'pseudocode_only', 'partial', 'none'];

function formatAddress(addr: string): string {
  if (addr.startsWith('0x') || addr.startsWith('0X')) {
    return addr.toUpperCase();
  }
  // Try to parse as hex
  const num = parseInt(addr, 16);
  if (!isNaN(num)) {
    return '0x' + num.toString(16).toUpperCase();
  }
  return addr;
}

function BlockMatrix({ functions, onSelect }: { functions: CoverageFunction[]; onSelect: (f: CoverageFunction) => void }) {
  if (functions.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <Layers className="w-12 h-12 mb-4 opacity-20" />
        <p>No function coverage data yet.</p>
        <p className="text-xs mt-2">Start analyzing functions to see coverage.</p>
      </div>
    );
  }

  return (
    <div className="flex flex-wrap gap-0.5">
      {functions.map((func) => {
        const colors = STATUS_COLORS[func.coverage_status] || STATUS_COLORS.none;
        return (
          <button
            key={func.address}
            onClick={() => onSelect(func)}
            title={`${formatAddress(func.address)}: ${colors.label}`}
            className={`w-4 h-6 flex-shrink-0 ${colors.bg} ${colors.border} border rounded-sm hover:opacity-80 transition-opacity`}
          />
        );
      })}
    </div>
  );
}

function CoverageStats({ coverage, total }: { coverage: CoverageData['coverage']; total: number }) {
  const viewed = coverage.disasm_only + coverage.pseudocode_only + coverage.both + coverage.full + coverage.partial;
  const percentage = total > 0 ? Math.round((viewed / total) * 100) : 0;

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2 mb-4">
      {STATUS_ORDER.map((status) => {
        const colors = STATUS_COLORS[status];
        const count = coverage[status as keyof typeof coverage] || 0;
        return (
          <div
            key={status}
            className={`p-3 rounded-lg border ${colors.bg.replace('bg-', 'bg-').replace('500', '500/10')} ${colors.border.replace('600', '300')} ${status === 'none' ? 'bg-slate-100 dark:bg-slate-800' : ''}`}
          >
            <div className="flex items-center gap-2 mb-1">
              <div className={`w-3 h-3 rounded-sm ${colors.bg}`} />
              <span className="text-xs text-muted-foreground">{colors.label}</span>
            </div>
            <div className="text-xl font-bold">{count}</div>
          </div>
        );
      })}
      <div className="p-3 rounded-lg border bg-green-500/10 border-green-300 dark:border-green-800">
        <div className="flex items-center gap-2 mb-1">
          <div className="w-3 h-3 rounded-sm bg-green-500" />
          <span className="text-xs text-muted-foreground">Coverage</span>
        </div>
        <div className="text-xl font-bold">{percentage}%</div>
      </div>
    </div>
  );
}

export function CoverageView() {
  const [selectedBinary, setSelectedBinary] = useState<string>('');
  const [selectedFunction, setSelectedFunction] = useState<CoverageFunction | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  // Get binaries from project
  const { data: binariesData } = useQuery({
    queryKey: ['projectBinaries'],
    queryFn: () => auditApi.getBinaries(),
  });

  const binaries = useMemo(() => {
    if (!binariesData) return [];
    return binariesData.map(b => b.binary_name).filter(Boolean);
  }, [binariesData]);

  useEffect(() => {
    if (binaries.length > 0 && !selectedBinary) {
      setSelectedBinary(binaries[0]);
    }
  }, [binaries, selectedBinary]);

  const { data: coverageData, isLoading } = useQuery({
    queryKey: ['browseCoverage', selectedBinary],
    queryFn: () => auditApi.getBrowseCoverage(selectedBinary),
    enabled: !!selectedBinary,
  });

  const filteredFunctions = useMemo(() => {
    if (!coverageData?.data?.functions) return [];
    if (!searchTerm) return coverageData.data.functions;
    const term = searchTerm.toLowerCase();
    return coverageData.data.functions.filter(f =>
      f.address.toLowerCase().includes(term) ||
      f.target_value.toLowerCase().includes(term)
    );
  }, [coverageData, searchTerm]);

  if (binaries.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
        <Layers className="w-12 h-12 mb-4 opacity-20" />
        <p>No binaries found.</p>
        <p className="text-xs mt-2">Load a binary first to see coverage.</p>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header with binary selector and search */}
      <div className="flex items-center gap-4 mb-4 shrink-0">
        <select
          value={selectedBinary}
          onChange={(e) => setSelectedBinary(e.target.value)}
          className="px-3 py-2 rounded-md border bg-background text-sm font-medium"
        >
          {binaries.map(bin => (
            <option key={bin} value={bin}>{bin}</option>
          ))}
        </select>
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search by address..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-2 rounded-md border bg-background text-sm"
          />
        </div>
        <div className="text-sm text-muted-foreground">
          {filteredFunctions.length} functions
        </div>
      </div>

      {/* Coverage Stats */}
      {coverageData?.data && (
        <CoverageStats coverage={coverageData.data.coverage} total={coverageData.data.total_functions} />
      )}

      {/* Block Matrix */}
      <div className="flex-1 min-h-0 overflow-auto bg-slate-50 dark:bg-slate-900 rounded-lg p-4 border">
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full" />
          </div>
        ) : (
          <BlockMatrix
            functions={filteredFunctions}
            onSelect={setSelectedFunction}
          />
        )}
      </div>

      {/* Selected Function Detail */}
      {selectedFunction && (
        <div className="mt-4 p-4 rounded-lg border bg-card shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`w-4 h-4 rounded-sm ${STATUS_COLORS[selectedFunction.coverage_status]?.bg || STATUS_COLORS.none.bg}`} />
              <span className="font-mono font-bold">{formatAddress(selectedFunction.address)}</span>
              <span className="text-muted-foreground">|</span>
              <span className="text-sm">{STATUS_COLORS[selectedFunction.coverage_status]?.label || 'Unknown'}</span>
            </div>
            <button onClick={() => setSelectedFunction(null)} className="text-muted-foreground hover:text-foreground">
              &times;
            </button>
          </div>
          <div className="mt-2 flex gap-4 text-sm">
            <div className={`flex items-center gap-1 ${selectedFunction.has_disasm ? 'text-blue-600' : 'text-muted-foreground'}`}>
              <Code2 className="w-4 h-4" />
              Disassembly {selectedFunction.has_disasm ? '✓' : '✗'}
            </div>
            <div className={`flex items-center gap-1 ${selectedFunction.has_pseudocode ? 'text-emerald-600' : 'text-muted-foreground'}`}>
              <FileCode className="w-4 h-4" />
              Pseudocode {selectedFunction.has_pseudocode ? '✓' : '✗'}
            </div>
            <div className={`flex items-center gap-1 ${selectedFunction.has_other ? 'text-purple-600' : 'text-muted-foreground'}`}>
              <MoreHorizontal className="w-4 h-4" />
              Other {selectedFunction.has_other ? '✓' : '✗'}
            </div>
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="mt-4 flex items-center gap-4 text-xs text-muted-foreground shrink-0">
        <span>Color Legend:</span>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded-sm bg-slate-300 dark:bg-slate-700" />
          <span>Not Viewed</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded-sm bg-blue-500" />
          <span>Disasm Only</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded-sm bg-emerald-500" />
          <span>Pseudocode Only</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded-sm bg-amber-500" />
          <span>Both</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded-sm bg-orange-500" />
          <span>Full</span>
        </div>
      </div>
    </div>
  );
}