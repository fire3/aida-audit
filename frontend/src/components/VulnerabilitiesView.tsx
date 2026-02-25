import { useState, useEffect } from 'react';
import { type Vulnerability } from '../api/client';
import { Badge, VerificationStatusBadge } from './AuditBadge';
import { formatAddress } from '../lib/utils';
import { AlertTriangle, CheckCircle2, Code } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

export function VulnerabilitiesView({ vulnerabilities }: { vulnerabilities: Vulnerability[] }) {
    const [selectedVulnerabilityId, setSelectedVulnerabilityId] = useState<number | null>(null);

    useEffect(() => {
        if (!selectedVulnerabilityId && vulnerabilities.length > 0) {
            setSelectedVulnerabilityId(vulnerabilities[0].id);
        }
    }, [selectedVulnerabilityId, vulnerabilities]);

    const selectedVulnerability = vulnerabilities.find(f => f.id === selectedVulnerabilityId);

    return (
        <div className="h-full flex gap-4">
            <div className="w-80 border-r pr-4 overflow-auto shrink-0">
                <h3 className="font-semibold mb-4 flex items-center gap-2 text-sm">
                    <AlertTriangle className="w-4 h-4 text-red-500" />
                    Security Vulnerabilities ({vulnerabilities.length})
                </h3>
                <div className="space-y-2">
                    {vulnerabilities.map(vulnerability => (
                        <button
                            key={vulnerability.id}
                            onClick={() => setSelectedVulnerabilityId(vulnerability.id)}
                            className={`w-full text-left p-3 rounded-lg border transition-all ${
                                selectedVulnerabilityId === vulnerability.id 
                                    ? 'bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-600' 
                                    : 'bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 border-slate-200 dark:border-slate-800'
                            }`}
                        >
                            <div className="flex items-center justify-between mb-1">
                                <div className="flex gap-2">
                                    <Badge variant={vulnerability.severity === 'critical' ? 'destructive' : vulnerability.severity === 'high' ? 'destructive' : vulnerability.severity === 'medium' ? 'warning' : 'info'}>
                                        {vulnerability.severity}
                                    </Badge>
                                    <VerificationStatusBadge status={vulnerability.verification_status} />
                                </div>
                                <span className="text-[10px] text-muted-foreground">
                                    {new Date(vulnerability.created_at).toLocaleDateString()}
                                </span>
                            </div>
                            <div className="font-medium text-sm line-clamp-2 mb-1">{vulnerability.title || vulnerability.category}</div>
                            <div className="text-xs text-muted-foreground truncate">
                                {vulnerability.binary_name}
                            </div>
                        </button>
                    ))}
                    {vulnerabilities.length === 0 && (
                        <div className="text-center text-muted-foreground py-8 text-sm">
                            No vulnerabilities yet.
                        </div>
                    )}
                </div>
            </div>
            
            <div className="flex-1 overflow-auto">
                {selectedVulnerability ? (
                    <div className="space-y-4">
                        <div className="border-b pb-4">
                            <div className="flex items-center justify-between mb-2">
                                <div className="flex items-center gap-2">
                                    <Badge variant={selectedVulnerability.severity === 'critical' ? 'destructive' : selectedVulnerability.severity === 'high' ? 'destructive' : selectedVulnerability.severity === 'medium' ? 'warning' : 'info'}>
                                        {selectedVulnerability.severity.toUpperCase()}
                                    </Badge>
                                    <span className="text-sm font-mono text-muted-foreground uppercase">{selectedVulnerability.category}</span>
                                </div>
                                <VerificationStatusBadge status={selectedVulnerability.verification_status} />
                            </div>
                            <h2 className="text-xl font-bold">{selectedVulnerability.title || "Untitled Vulnerability"}</h2>
                            <div className="text-xs text-muted-foreground mt-2 flex items-center gap-4">
                                <span>ID: {selectedVulnerability.id}</span>
                                <span>Found: {new Date(selectedVulnerability.created_at).toLocaleString()}</span>
                                <div className="flex items-center gap-1">
                                    <Code className="w-3 h-3" />
                                    <span className="font-mono">{selectedVulnerability.binary_name}</span>
                                </div>
                            </div>
                        </div>
                        
                        {selectedVulnerability.verification_details && (
                            <div className={`border rounded-lg p-4 ${selectedVulnerability.verification_status === 'confirmed' ? 'bg-red-50 dark:bg-red-900/10 border-red-200 dark:border-red-900' : 'bg-slate-50 dark:bg-slate-900/50'}`}>
                                <h3 className="font-semibold text-sm mb-2 flex items-center gap-2">
                                    <CheckCircle2 className="w-4 h-4" />
                                    Verification Report
                                </h3>
                                <div className="prose prose-sm dark:prose-invert max-w-none">
                                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                        {selectedVulnerability.verification_details}
                                    </ReactMarkdown>
                                </div>
                            </div>
                        )}
                        
                        {(selectedVulnerability.function_name || selectedVulnerability.address) && (
                            <div className="bg-slate-50 dark:bg-slate-900/50 p-3 rounded-lg border flex items-center gap-4 text-sm font-mono">
                                {selectedVulnerability.function_name && (
                                    <div className="flex items-center gap-2">
                                        <span className="text-muted-foreground">Function:</span>
                                        <span className="text-purple-600 dark:text-purple-400">{selectedVulnerability.function_name}</span>
                                    </div>
                                )}
                                {selectedVulnerability.address && (
                                    <div className="flex items-center gap-2">
                                        <span className="text-muted-foreground">Address:</span>
                                        <span className="text-slate-700 dark:text-slate-300">{formatAddress(selectedVulnerability.address)}</span>
                                    </div>
                                )}
                            </div>
                        )}

                        <div>
                            <h3 className="font-semibold text-sm mb-2">Description</h3>
                            <div className="prose prose-sm dark:prose-invert max-w-none p-4 border rounded-lg bg-slate-50/50 dark:bg-slate-900/20">
                                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                    {selectedVulnerability.description}
                                </ReactMarkdown>
                            </div>
                        </div>

                        {selectedVulnerability.evidence && (
                            <div>
                                <h3 className="font-semibold text-sm mb-2">Evidence / Code Snippet</h3>
                                <div className="bg-slate-900 text-slate-200 p-4 rounded-lg font-mono text-xs overflow-x-auto">
                                    <pre>{selectedVulnerability.evidence}</pre>
                                </div>
                            </div>
                        )}

                        <div className="grid grid-cols-2 gap-4 mt-4">
                            {selectedVulnerability.cvss && (
                                <div className="border rounded p-3">
                                    <div className="text-xs text-muted-foreground mb-1">CVSS Score</div>
                                    <div className="font-mono font-bold">{selectedVulnerability.cvss}</div>
                                </div>
                            )}
                            {selectedVulnerability.exploitability && (
                                <div className="border rounded p-3">
                                    <div className="text-xs text-muted-foreground mb-1">Exploitability</div>
                                    <div className="font-medium">{selectedVulnerability.exploitability}</div>
                                </div>
                            )}
                        </div>
                    </div>
                ) : (
                    <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                        <AlertTriangle className="w-12 h-12 mb-4 opacity-20" />
                        <p>Select a vulnerability to view details</p>
                    </div>
                )}
            </div>
        </div>
    );
}
