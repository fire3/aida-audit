import { useState, useEffect } from 'react';
import { type Note } from '../api/client';
import { Badge } from './AuditBadge';
import { formatAddress } from '../lib/utils';
import { StickyNote, Code } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

export function NotesView({ notes }: { notes: Note[] }) {
    const [selectedNoteId, setSelectedNoteId] = useState<number | null>(null);

    useEffect(() => {
        if (!selectedNoteId && notes.length > 0) {
            setSelectedNoteId(notes[0].note_id);
        }
    }, [selectedNoteId, notes]);

    const selectedNote = notes.find(n => n.note_id === selectedNoteId);

    return (
        <div className="h-full flex gap-4">
            <div className="w-80 border-r pr-4 overflow-auto shrink-0">
                <h3 className="font-semibold mb-4 flex items-center gap-2 text-sm">
                    <StickyNote className="w-4 h-4 text-blue-500" />
                    Analysis Notes ({notes.length})
                </h3>
                <div className="space-y-2">
                    {notes.map(note => (
                        <button
                            key={note.note_id}
                            onClick={() => setSelectedNoteId(note.note_id)}
                            className={`w-full text-left p-3 rounded-lg border transition-all ${
                                selectedNoteId === note.note_id 
                                    ? 'bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-600' 
                                    : 'bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 border-slate-200 dark:border-slate-800'
                            }`}
                        >
                            <div className="flex items-center justify-between mb-1">
                                <Badge variant="outline">
                                    {note.note_type}
                                </Badge>
                                <span className="text-[10px] text-muted-foreground">
                                    {new Date(note.created_at).toLocaleDateString()}
                                </span>
                            </div>
                            <div className="font-medium text-sm line-clamp-2 mb-1">{note.title || "Untitled Note"}</div>
                            <div className="text-xs text-muted-foreground truncate">
                                {note.binary_name}
                            </div>
                            {note.tags && note.tags.length > 0 && (
                                <div className="flex flex-wrap gap-1 mt-2">
                                    {note.tags.slice(0, 3).map(tag => (
                                        <span key={tag} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-1.5 py-0.5 rounded text-slate-700 dark:text-slate-300">#{tag}</span>
                                    ))}
                                    {note.tags.length > 3 && (
                                        <span className="text-[10px] text-muted-foreground">+{note.tags.length - 3}</span>
                                    )}
                                </div>
                            )}
                        </button>
                    ))}
                    {notes.length === 0 && (
                        <div className="text-center text-muted-foreground py-8 text-sm">
                            No notes yet.
                        </div>
                    )}
                </div>
            </div>
            
            <div className="flex-1 overflow-auto">
                {selectedNote ? (
                    <div className="space-y-4">
                        <div className="border-b pb-4">
                            <div className="flex items-center gap-2 mb-2">
                                <Badge variant="outline">
                                    {selectedNote.note_type.toUpperCase()}
                                </Badge>
                                <span className="text-sm font-mono text-muted-foreground uppercase">{selectedNote.confidence} Confidence</span>
                            </div>
                            <h2 className="text-xl font-bold">{selectedNote.title || "Untitled Note"}</h2>
                            <div className="text-xs text-muted-foreground mt-2 flex items-center gap-4">
                                <span>ID: {selectedNote.note_id}</span>
                                <span>Created: {new Date(selectedNote.created_at).toLocaleString()}</span>
                                <div className="flex items-center gap-1">
                                    <Code className="w-3 h-3" />
                                    <span className="font-mono">{selectedNote.binary_name}</span>
                                </div>
                            </div>
                        </div>
                        
                        {(selectedNote.function_name || selectedNote.address) && (
                            <div className="bg-slate-50 dark:bg-slate-900/50 p-3 rounded-lg border flex items-center gap-4 text-sm font-mono">
                                {selectedNote.function_name && (
                                    <div className="flex items-center gap-2">
                                        <span className="text-muted-foreground">Function:</span>
                                        <span className="text-purple-600 dark:text-purple-400">{selectedNote.function_name}</span>
                                    </div>
                                )}
                                {selectedNote.address && (
                                    <div className="flex items-center gap-2">
                                        <span className="text-muted-foreground">Address:</span>
                                        <span className="text-slate-700 dark:text-slate-300">{formatAddress(selectedNote.address)}</span>
                                    </div>
                                )}
                            </div>
                        )}

                        <div>
                            <h3 className="font-semibold text-sm mb-2">Content</h3>
                            <div className="prose prose-sm dark:prose-invert max-w-none p-4 border rounded-lg bg-slate-50/50 dark:bg-slate-900/20">
                                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                    {selectedNote.content}
                                </ReactMarkdown>
                            </div>
                        </div>

                        {selectedNote.tags && selectedNote.tags.length > 0 && (
                            <div>
                                <h3 className="font-semibold text-sm mb-2">Tags</h3>
                                <div className="flex flex-wrap gap-2">
                                    {selectedNote.tags.map(tag => (
                                        <span key={tag} className="text-xs bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded border border-slate-200 dark:border-slate-700">
                                            #{tag}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                ) : (
                    <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                        <StickyNote className="w-12 h-12 mb-4 opacity-20" />
                        <p>Select a note to view details</p>
                    </div>
                )}
            </div>
        </div>
    );
}
