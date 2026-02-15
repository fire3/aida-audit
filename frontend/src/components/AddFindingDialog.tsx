import { useState, useEffect } from 'react';
import { useMutation, useQueryClient, useQuery } from '@tanstack/react-query';
import { notesApi, projectApi } from '../api/client';
import { Modal } from './ui/modal';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Textarea } from './ui/textarea';
import { Select } from './ui/select';
import { Loader2 } from 'lucide-react';

interface AddFindingDialogProps {
    isOpen: boolean;
    onClose: () => void;
    initialBinaryName?: string;
    initialFunctionName?: string;
    initialAddress?: string;
    onSuccess?: () => void;
}

const SEVERITY_LEVELS = [
    { value: 'critical', label: 'Critical' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'low', label: 'Low' },
    { value: 'info', label: 'Info' },
];

const CATEGORIES = [
    { value: 'vulnerability', label: 'Vulnerability' },
    { value: 'bug', label: 'Bug' },
    { value: 'suspicious', label: 'Suspicious Behavior' },
    { value: 'hardcoded_secret', label: 'Hardcoded Secret' },
    { value: 'logic_flaw', label: 'Logic Flaw' },
    { value: 'configuration', label: 'Configuration Issue' },
    { value: 'other', label: 'Other' },
];

const EXPLOITABILITY_LEVELS = [
    { value: 'unproven', label: 'Unproven' },
    { value: 'proof_of_concept', label: 'Proof of Concept' },
    { value: 'functional', label: 'Functional' },
    { value: 'high', label: 'High' },
];

export function AddFindingDialog({ 
    isOpen, 
    onClose, 
    initialBinaryName, 
    initialFunctionName, 
    initialAddress,
    onSuccess 
}: AddFindingDialogProps) {
    const queryClient = useQueryClient();
    const [binaryName, setBinaryName] = useState(initialBinaryName || '');
    const [severity, setSeverity] = useState('medium');
    const [category, setCategory] = useState('vulnerability');
    const [description, setDescription] = useState('');
    const [evidence, setEvidence] = useState('');
    const [cvss, setCvss] = useState<string>('');
    const [exploitability, setExploitability] = useState('');
    const [functionName, setFunctionName] = useState(initialFunctionName || '');
    const [address, setAddress] = useState(initialAddress || '');
    const [error, setError] = useState<string | null>(null);

    // Fetch binaries for the dropdown if binary name is not provided or editable
    const { data: binaries } = useQuery({
        queryKey: ['binaries'],
        queryFn: () => projectApi.listBinaries(),
        enabled: isOpen && !initialBinaryName,
    });

    useEffect(() => {
        if (isOpen) {
            setBinaryName(initialBinaryName || '');
            setFunctionName(initialFunctionName || '');
            setAddress(initialAddress || '');
            setSeverity('medium');
            setCategory('vulnerability');
            setDescription('');
            setEvidence('');
            setCvss('');
            setExploitability('');
            setError(null);
        }
    }, [isOpen, initialBinaryName, initialFunctionName, initialAddress]);

    const createFindingMutation = useMutation({
        mutationFn: notesApi.markFinding,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['findings'] });
            queryClient.invalidateQueries({ queryKey: ['analysis-progress'] });
            if (onSuccess) onSuccess();
            onClose();
        },
        onError: (err: any) => {
            setError(err.response?.data?.detail || err.message || 'Failed to create finding');
        }
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        
        if (!binaryName) {
            setError('Binary name is required');
            return;
        }

        if (!description.trim()) {
            setError('Description is required');
            return;
        }

        createFindingMutation.mutate({
            binary_name: binaryName,
            severity: severity,
            category: category,
            description: description,
            evidence: evidence || undefined,
            cvss: cvss ? parseFloat(cvss) : undefined,
            exploitability: exploitability || undefined,
            function_name: functionName || undefined,
            address: address || undefined,
        });
    };

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Add Finding" className="max-w-2xl">
            <form onSubmit={handleSubmit} className="space-y-4">
                {error && (
                    <div className="bg-destructive/15 text-destructive text-sm p-3 rounded-md">
                        {error}
                    </div>
                )}

                <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Binary</label>
                        {initialBinaryName ? (
                            <Input value={initialBinaryName} disabled className="bg-muted" />
                        ) : (
                            <Select 
                                value={binaryName} 
                                onChange={(e) => setBinaryName(e.target.value)}
                                disabled={!!initialBinaryName}
                            >
                                <option value="">Select Binary...</option>
                                {binaries?.map(b => (
                                    <option key={b.binary_name} value={b.binary_name}>
                                        {b.binary_name}
                                    </option>
                                ))}
                            </Select>
                        )}
                    </div>
                    
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Category</label>
                        <Select value={category} onChange={(e) => setCategory(e.target.value)}>
                            {CATEGORIES.map(c => (
                                <option key={c.value} value={c.value}>{c.label}</option>
                            ))}
                        </Select>
                    </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Function (Optional)</label>
                        <Input 
                            value={functionName} 
                            onChange={(e) => setFunctionName(e.target.value)} 
                            placeholder="e.g., main"
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Address (Optional)</label>
                        <Input 
                            value={address} 
                            onChange={(e) => setAddress(e.target.value)} 
                            placeholder="e.g., 0x401000"
                        />
                    </div>
                </div>

                <div className="space-y-2">
                    <label className="text-sm font-medium">Description</label>
                    <Textarea 
                        value={description} 
                        onChange={(e) => setDescription(e.target.value)} 
                        placeholder="Describe the finding..."
                        className="min-h-[100px]"
                    />
                </div>

                <div className="space-y-2">
                    <label className="text-sm font-medium">Evidence (Optional code snippet or trace)</label>
                    <Textarea 
                        value={evidence} 
                        onChange={(e) => setEvidence(e.target.value)} 
                        placeholder="Paste relevant code or evidence..."
                        className="min-h-[80px] font-mono text-xs"
                    />
                </div>

                <div className="grid grid-cols-3 gap-4">
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Severity</label>
                        <Select value={severity} onChange={(e) => setSeverity(e.target.value)}>
                            {SEVERITY_LEVELS.map(s => (
                                <option key={s.value} value={s.value}>{s.label}</option>
                            ))}
                        </Select>
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">CVSS Score (0-10)</label>
                        <Input 
                            type="number"
                            min="0"
                            max="10"
                            step="0.1"
                            value={cvss} 
                            onChange={(e) => setCvss(e.target.value)} 
                            placeholder="e.g. 7.5"
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Exploitability</label>
                        <Select value={exploitability} onChange={(e) => setExploitability(e.target.value)}>
                            <option value="">Unknown</option>
                            {EXPLOITABILITY_LEVELS.map(e => (
                                <option key={e.value} value={e.value}>{e.label}</option>
                            ))}
                        </Select>
                    </div>
                </div>

                <div className="flex justify-end space-x-2 pt-4">
                    <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
                    <Button type="submit" disabled={createFindingMutation.isPending}>
                        {createFindingMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        Add Finding
                    </Button>
                </div>
            </form>
        </Modal>
    );
}
