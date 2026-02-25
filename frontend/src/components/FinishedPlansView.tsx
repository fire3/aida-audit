import { useState, useEffect } from 'react';
import { auditApi, type AuditPlan } from '../api/client';
import { Badge } from './AuditBadge';
import { CheckCircle2, Archive, StickyNote } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

export function FinishedPlansView({ completedTasks }: { completedTasks: AuditPlan[] }) {
    const [selectedTaskId, setSelectedTaskId] = useState<number | null>(null);
    const [taskSummaries, setTaskSummaries] = useState<Record<number, string>>({});
    
    useEffect(() => {
        if (!selectedTaskId && completedTasks.length > 0) {
            setSelectedTaskId(completedTasks[0].id);
        }
    }, [selectedTaskId, completedTasks]);

    useEffect(() => {
        const fetchTaskSummary = async () => {
            const task = completedTasks.find(t => t.id === selectedTaskId);
            if (task && !task.summary && !taskSummaries[task.id]) {
                try {
                    const fullTask = await auditApi.getTask(task.id);
                    if (fullTask.summary) {
                        setTaskSummaries(prev => ({ ...prev, [task.id]: fullTask.summary! }));
                    }
                } catch (e) {
                    console.error('Failed to fetch task summary:', e);
                }
            }
        };
        if (selectedTaskId) {
            fetchTaskSummary();
        }
    }, [selectedTaskId, completedTasks]);
    
    const selectedTask = completedTasks.find(t => t.id === selectedTaskId);
    
    return (
        <div className="h-full flex gap-4">
            <div className="w-72 border-r pr-4 overflow-auto shrink-0">
                <h3 className="font-semibold mb-4 flex items-center gap-2 text-sm">
                    <Archive className="w-4 h-4 text-green-500" />
                    Completed Tasks ({completedTasks.length})
                </h3>
                <div className="space-y-2">
                    {completedTasks.map(task => (
                        <button
                            key={task.id}
                            onClick={() => setSelectedTaskId(task.id)}
                            className={`w-full text-left p-3 rounded-lg border transition-all ${
                                selectedTaskId === task.id 
                                    ? 'bg-green-50 dark:bg-green-950/30 border-green-300 dark:border-green-700' 
                                    : 'bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 border-slate-200 dark:border-slate-800'
                            }`}
                        >
                            <div className="flex items-center justify-between mb-1">
                                <CheckCircle2 className="w-4 h-4 text-green-500" />
                                <span className="text-[10px] text-muted-foreground">
                                    {new Date(task.updated_at * 1000).toLocaleDateString()}
                                </span>
                            </div>
                            <div className="font-medium text-sm line-clamp-2">{task.title}</div>
                            <div className="text-xs text-muted-foreground mt-1">
                                {task.plan_type === 'agent_plan' ? 'Agent Task' : task.plan_type === 'verification_plan' ? 'Verification Task' : 'Plan'}
                            </div>
                        </button>
                    ))}
                    {completedTasks.length === 0 && (
                        <div className="text-center text-muted-foreground py-8 text-sm">
                            No completed tasks yet.
                        </div>
                    )}
                </div>
            </div>
            
            <div className="flex-1 overflow-auto">
                {selectedTask ? (
                    <div className="space-y-4">
                        <div className="border-b pb-4">
                            <div className="flex items-center gap-2 mb-2">
                                <CheckCircle2 className="w-5 h-5 text-green-500" />
                                <Badge variant="default">Completed</Badge>
                            </div>
                            <h2 className="text-xl font-bold">{selectedTask.title}</h2>
                            <p className="text-sm text-muted-foreground mt-1">{selectedTask.description}</p>
                            {selectedTask.binary_name && (
                                <div className="text-xs font-mono text-purple-600 dark:text-purple-400 mt-2">
                                    Target: {selectedTask.binary_name}
                                </div>
                            )}
                            <div className="text-xs text-muted-foreground mt-2 flex items-center gap-4">
                                <span>ID: {selectedTask.id}</span>
                                <span>Updated: {new Date(selectedTask.updated_at * 1000).toLocaleString()}</span>
                            </div>
                        </div>
                        
                        {(selectedTask.summary || taskSummaries[selectedTask.id]) && (
                            <div className="border rounded-lg overflow-hidden">
                                <div className="bg-green-50 dark:bg-green-950/30 px-4 py-2 border-b border-green-200 dark:border-green-900">
                                    <h3 className="font-semibold text-sm flex items-center gap-2 text-green-700 dark:text-green-400">
                                        <StickyNote className="w-4 h-4" />
                                        Summary
                                    </h3>
                                </div>
                                <div className="p-4 prose prose-sm dark:prose-invert max-w-none 
                                    prose-headings:font-semibold prose-headings:mt-4 prose-headings:mb-2
                                    prose-p:my-2 prose-p:leading-relaxed
                                    prose-ul:my-2 prose-ul:pl-4 prose-li:my-0.5
                                    prose-ol:my-2 prose-ol:pl-4 prose-li:my-0.5
                                    prose-code:bg-slate-100 dark:prose-code:bg-slate-800 prose-code:px-1 prose-code:rounded prose-code:text-purple-600 dark:prose-code:text-purple-400
                                    prose-pre:bg-slate-900 dark:prose-pre:bg-slate-950 prose-pre:text-sm prose-pre:p-3 prose-pre:rounded-lg
                                    prose-strong:text-slate-900 dark:prose-strong:text-slate-100
                                    prose-blockquote:border-l-green-500 prose-blockquote:bg-green-50 dark:prose-blockquote:bg-green-950/30 prose-blockquote:py-1 prose-blockquote:px-3 prose-blockquote:not-italic
                                    prose-hr:border-slate-200 dark:prose-hr:border-slate-800">
                                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                        {selectedTask.summary || taskSummaries[selectedTask.id]}
                                    </ReactMarkdown>
                                </div>
                            </div>
                        )}
                    </div>
                ) : (
                    <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                        <Archive className="w-12 h-12 mb-4 opacity-20" />
                        <p>Select a completed task to view details</p>
                    </div>
                )}
            </div>
        </div>
    );
}
