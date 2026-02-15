import { useState, useEffect } from 'react';
import { useMutation, useQueryClient, useQuery } from '@tanstack/react-query';
import { notesApi, projectApi } from '../api/client';
import { Modal } from './ui/modal';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Textarea } from './ui/textarea';
import { Select } from './ui/select';
import { Loader2 } from 'lucide-react';

interface AddNoteDialogProps {
    isOpen: boolean;
    onClose: () => void;
    initialBinaryName?: string;
    initialFunctionName?: string;
    initialAddress?: string;
    onSuccess?: () => void;
}

const NOTE_TYPES = [
    { value: 'general', label: 'General Note' },
    { value: 'function_summary', label: 'Function Summary' },
    { value: 'vulnerability_hint', label: 'Vulnerability Hint' },
    { value: 'data_structure', label: 'Data Structure' },
    { value: 'reverse_engineering', label: 'Reverse Engineering' },
    { value: 'todo', label: 'To Do' },
];

const CONFIDENCE_LEVELS = [
    { value: 'low', label: 'Low Confidence' },
    { value: 'medium', label: 'Medium Confidence' },
    { value: 'high', label: 'High Confidence' },
];

export function AddNoteDialog({ 
    isOpen, 
    onClose, 
    initialBinaryName, 
    initialFunctionName, 
    initialAddress,
    onSuccess 
}: AddNoteDialogProps) {
    const queryClient = useQueryClient();
    const [binaryName, setBinaryName] = useState(initialBinaryName || '');
    const [noteType, setNoteType] = useState('general');
    const [content, setContent] = useState('');
    const [tags, setTags] = useState('');
    const [confidence, setConfidence] = useState('medium');
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
            setNoteType(initialFunctionName ? 'function_summary' : 'general');
            setContent('');
            setTags('');
            setConfidence('medium');
            setError(null);
        }
    }, [isOpen, initialBinaryName, initialFunctionName, initialAddress]);

    const createNoteMutation = useMutation({
        mutationFn: notesApi.createNote,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['notes'] });
            queryClient.invalidateQueries({ queryKey: ['analysis-progress'] });
            if (onSuccess) onSuccess();
            onClose();
        },
        onError: (err: any) => {
            setError(err.response?.data?.detail || err.message || 'Failed to create note');
        }
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        
        if (!binaryName) {
            setError('Binary name is required');
            return;
        }

        if (!content.trim()) {
            setError('Content is required');
            return;
        }

        createNoteMutation.mutate({
            binary_name: binaryName,
            note_type: noteType,
            content: content,
            tags: tags,
            confidence: confidence,
            function_name: functionName || undefined,
            address: address || undefined,
        });
    };

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Add Note" className="max-w-xl">
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
                        <label className="text-sm font-medium">Note Type</label>
                        <Select value={noteType} onChange={(e) => setNoteType(e.target.value)}>
                            {NOTE_TYPES.map(t => (
                                <option key={t.value} value={t.value}>{t.label}</option>
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
                    <label className="text-sm font-medium">Content</label>
                    <Textarea 
                        value={content} 
                        onChange={(e) => setContent(e.target.value)} 
                        placeholder="Enter note content..."
                        className="min-h-[120px]"
                    />
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Tags (comma separated)</label>
                        <Input 
                            value={tags} 
                            onChange={(e) => setTags(e.target.value)} 
                            placeholder="e.g., encryption, key, todo"
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-medium">Confidence</label>
                        <Select value={confidence} onChange={(e) => setConfidence(e.target.value)}>
                            {CONFIDENCE_LEVELS.map(c => (
                                <option key={c.value} value={c.value}>{c.label}</option>
                            ))}
                        </Select>
                    </div>
                </div>

                <div className="flex justify-end space-x-2 pt-4">
                    <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
                    <Button type="submit" disabled={createNoteMutation.isPending}>
                        {createNoteMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        Add Note
                    </Button>
                </div>
            </form>
        </Modal>
    );
}
