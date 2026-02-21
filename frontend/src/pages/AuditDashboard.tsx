import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { auditApi, type AuditPlan, type AuditMessage, type Vulnerability, type Note } from '../api/client';
import { Card, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { useState, useMemo, useEffect, useRef } from 'react';
import {
  CheckCircle2, 
  Circle, 
  Clock, 
  AlertCircle, 
  Terminal, 
  MessageSquare, 
  ListTodo,
  Play,
  Square,
  StickyNote,
  AlertTriangle,
  Code,
  Archive,
  ShieldCheck
} from 'lucide-react';
import { formatAddress } from '../lib/utils';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

function Badge({ children, variant }: { children: React.ReactNode, variant: string }) {
    const colors = {
        default: "bg-green-100 text-green-800 border border-green-200",
        secondary: "bg-blue-100 text-blue-800 border border-blue-200",
        outline: "bg-gray-100 text-gray-800 border border-gray-200",
        destructive: "bg-red-100 text-red-800 border border-red-200",
        warning: "bg-yellow-100 text-yellow-800 border border-yellow-200",
        info: "bg-sky-100 text-sky-800 border border-sky-200",
        purple: "bg-purple-100 text-purple-800 border border-purple-200",
        orange: "bg-orange-100 text-orange-800 border border-orange-200"
    };
    const style = colors[variant as keyof typeof colors] || colors.outline;
    return (
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wide ${style}`}>
            {children}
        </span>
    )
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'completed': return <CheckCircle2 className="w-4 h-4 text-green-500" />;
    case 'in_progress': return <Clock className="w-4 h-4 text-blue-500 animate-pulse" />;
    case 'failed': return <AlertCircle className="w-4 h-4 text-red-500" />;
    default: return <Circle className="w-4 h-4 text-gray-300" />;
  }
}

function VerificationStatusBadge({ status }: { status: string | undefined }) {
  if (!status) status = 'unverified';
  const colors: Record<string, string> = {
    unverified: "bg-slate-100 text-slate-500 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700",
    confirmed: "bg-red-100 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-900",
    false_positive: "bg-green-100 text-green-700 border-green-200 dark:bg-green-900/30 dark:text-green-400 dark:border-green-900",
  };
  const style = colors[status] || colors.unverified;
  const icon = status === 'confirmed' ? <AlertTriangle className="w-3 h-3 mr-1" /> : 
               status === 'false_positive' ? <CheckCircle2 className="w-3 h-3 mr-1" /> :
               <Circle className="w-3 h-3 mr-1" />;
               
  return (
      <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wide border flex items-center ${style}`}>
          {icon}
          {status.replace('_', ' ')}
      </span>
  )
}

function UserPromptConfig() {
    const [isEditing, setIsEditing] = useState(false);
    const [prompt, setPrompt] = useState("");
    const [loading, setLoading] = useState(false);

    const { data, refetch } = useQuery({ 
        queryKey: ['userPrompt'], 
        queryFn: auditApi.getUserPrompt,
        refetchOnWindowFocus: false
    });

    useEffect(() => {
        if (data) {
            setPrompt(data.content);
        }
    }, [data]);

    const handleSave = async () => {
        setLoading(true);
        try {
            await auditApi.updateUserPrompt(prompt);
            await refetch();
            setIsEditing(false);
        } catch (error) {
            console.error("Failed to save prompt", error);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="mb-4 border rounded-lg p-3 bg-white dark:bg-slate-900 shadow-sm">
            <div className="flex items-center justify-between mb-2">
                <h3 className="font-semibold text-sm flex items-center gap-2">
                    <MessageSquare className="w-4 h-4 text-blue-500" />
                    User Requirements (Macro Goal)
                </h3>
                {!isEditing && (
                    <Button variant="ghost" size="sm" onClick={() => setIsEditing(true)} className="h-6 text-xs">
                        Edit
                    </Button>
                )}
            </div>
            
            {isEditing ? (
                <div className="space-y-2">
                    <textarea 
                        className="w-full text-xs p-2 border rounded bg-slate-50 dark:bg-slate-800 min-h-[60px] focus:outline-none focus:ring-1 focus:ring-blue-500"
                        placeholder="Enter your specific requirements or macro goals for the audit..."
                        value={prompt}
                        onChange={(e) => setPrompt(e.target.value)}
                    />
                    <div className="flex justify-end gap-2">
                        <Button variant="ghost" size="sm" onClick={() => {
                            setIsEditing(false);
                            setPrompt(data?.content || "");
                        }} className="h-7 text-xs">
                            Cancel
                        </Button>
                        <Button size="sm" onClick={handleSave} disabled={loading} className="h-7 text-xs">
                            {loading ? "Saving..." : "Save"}
                        </Button>
                    </div>
                </div>
            ) : (
                <div className="text-xs text-muted-foreground">
                    {prompt ? (
                        <p className="whitespace-pre-wrap">{prompt}</p>
                    ) : (
                        <p className="italic opacity-70">No specific requirements set. Click Edit to add instructions for the agent.</p>
                    )}
                </div>
            )}
        </div>
    );
}

function PlanView({ plans }: { plans: AuditPlan[] }) {
    const macroPlans = useMemo(() => plans.filter(p => p.plan_type === 'audit_plan'), [plans]);
    const agentTasks = useMemo(() => 
        plans.filter(p => p.plan_type === 'agent_plan').sort((a, b) => b.id - a.id), 
        [plans]
    );
    const verificationTasks = useMemo(() => 
        plans.filter(p => p.plan_type === 'verification_plan').sort((a, b) => b.id - a.id),
        [plans]
    );

    const allExecutionTasks = useMemo(() => 
        [...agentTasks, ...verificationTasks].sort((a, b) => b.id - a.id),
        [agentTasks, verificationTasks]
    );

    return (
        <div className="h-full flex gap-4">
            <div className="w-1/3 border-r pr-4 overflow-auto">
                <UserPromptConfig />
                <h3 className="font-semibold mb-4 flex items-center gap-2">
                    <ListTodo className="w-4 h-4 text-purple-500" />
                    Audit Strategy
                </h3>
                <div className="space-y-4">
                    {macroPlans.map(plan => (
                        <div key={plan.id} className="border rounded-lg p-3 bg-purple-50/30 dark:bg-purple-900/10">
                            <div className="flex items-center justify-between mb-2">
                                <span className="font-medium text-sm">{plan.title}</span>
                                <StatusIcon status={plan.status} />
                            </div>
                            <p className="text-xs text-muted-foreground mb-2">{plan.description}</p>
                            
                            <div className="space-y-1 mt-3 pl-2 border-l-2 border-slate-200 dark:border-slate-800">
                                <div className="text-[10px] uppercase font-bold text-muted-foreground mb-1">Tasks</div>
                                
                                {agentTasks.filter(t => t.plan_id === plan.id).map(task => (
                                    <div key={task.id} className="flex items-center gap-2 text-xs py-1">
                                        <StatusIcon status={task.status} />
                                        <span className={`${task.status === 'completed' ? 'line-through text-muted-foreground' : ''}`}>
                                            {task.title}
                                        </span>
                                    </div>
                                ))}

                                {verificationTasks.filter(t => t.plan_id === plan.id).map(task => (
                                    <div key={task.id} className="flex items-center gap-2 text-xs py-1">
                                        <StatusIcon status={task.status} />
                                        <ShieldCheck className="w-3 h-3 text-blue-500" />
                                        <span className={`${task.status === 'completed' ? 'line-through text-muted-foreground' : ''}`}>
                                            {task.title}
                                        </span>
                                    </div>
                                ))}

                                {agentTasks.filter(t => t.plan_id === plan.id).length === 0 && verificationTasks.filter(t => t.plan_id === plan.id).length === 0 && (
                                    <div className="text-[10px] text-muted-foreground italic">No tasks assigned yet</div>
                                )}
                            </div>
                        </div>
                    ))}
                    {macroPlans.length === 0 && (
                        <div className="text-center text-muted-foreground py-8">
                            No audit plans defined.
                        </div>
                    )}
                </div>
            </div>

            <div className="flex-1 overflow-auto">
                 <h3 className="font-semibold mb-4 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-orange-500" />
                    Task Execution Stream
                </h3>
                <div className="space-y-3">
                    {allExecutionTasks.length > 0 ? (
                        allExecutionTasks.map(task => {
                            const parentPlan = macroPlans.find(p => p.id === task.plan_id);
                            const isVerification = task.plan_type === 'verification_plan';
                            return (
                             <div key={task.id} className={`group relative border rounded-lg p-3 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-all hover:shadow-sm bg-white dark:bg-slate-900 ${isVerification ? 'border-l-4 border-l-blue-400' : ''}`}>
                                {/* Header Row: ID, Title, Status */}
                                <div className="flex items-center justify-between gap-3 mb-2">
                                    <div className="flex items-center gap-2 overflow-hidden">
                                        <div className={`flex items-center justify-center w-6 h-6 rounded-full shrink-0 border border-slate-200 dark:border-slate-700 ${isVerification ? 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400' : 'bg-slate-100 dark:bg-slate-800 text-slate-500'}`}>
                                            {isVerification ? <ShieldCheck className="w-3 h-3" /> : <span className="text-[10px] font-mono font-bold">#{task.id}</span>}
                                        </div>
                                        <h4 className="font-semibold text-sm truncate text-slate-800 dark:text-slate-200" title={task.title}>
                                            {task.title}
                                        </h4>
                                    </div>
                                    <div className="flex items-center gap-2 shrink-0">
                                         <StatusIcon status={task.status} />
                                         <Badge variant={task.status === 'completed' ? 'default' : task.status === 'in_progress' ? 'secondary' : task.status === 'failed' ? 'destructive' : 'outline'}>
                                            {task.status}
                                        </Badge>
                                    </div>
                                </div>

                                {/* Description Area - Fixed Height */}
                                <div className="bg-slate-50 dark:bg-slate-950/50 rounded-md p-2.5 mb-2 border border-slate-100 dark:border-slate-800 h-24 overflow-y-auto custom-scrollbar">
                                    <p className="text-xs text-muted-foreground whitespace-pre-wrap leading-relaxed font-mono">
                                        {task.description || "No description provided."}
                                    </p>
                                </div>

                                {/* Footer Metadata Row */}
                                <div className="flex items-center justify-between text-[10px] text-muted-foreground mt-2 pt-2 border-t border-dashed border-slate-100 dark:border-slate-800">
                                    <div className="flex items-center gap-3 overflow-hidden">
                                        {/* Parent Plan */}
                                        {parentPlan && (
                                            <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-purple-50 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300 border border-purple-100 dark:border-purple-800/30 shrink-0 max-w-[200px]">
                                                <ListTodo className="w-3 h-3 shrink-0" />
                                                <span className="font-medium truncate" title={parentPlan.title}>
                                                    Parent: {parentPlan.title}
                                                </span>
                                            </div>
                                        )}
                                        
                                        {/* Binary Target */}
                                        {task.binary_name && (
                                            <div className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 shrink-0">
                                                <Code className="w-3 h-3" />
                                                <span className="font-mono">{task.binary_name}</span>
                                            </div>
                                        )}
                                    </div>

                                    {/* Timestamp */}
                                    <div className="flex items-center gap-1 opacity-70 shrink-0 ml-2">
                                        <Clock className="w-3 h-3" />
                                        <span>{new Date(task.updated_at * 1000).toLocaleString()}</span>
                                    </div>
                                </div>
                             </div>
                            );
                        })
                    ) : (
                        <div className="flex flex-col items-center justify-center h-64 text-muted-foreground border rounded-lg bg-slate-50/50 dark:bg-slate-900/20 border-dashed">
                            <ListTodo className="w-12 h-12 mb-4 opacity-20" />
                            <p>No tasks generated yet.</p>
                            <p className="text-xs mt-2">Set your requirements on the left and start the audit.</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

function FinishedPlansView({ completedTasks }: { completedTasks: AuditPlan[] }) {
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
            {/* Left: List of completed tasks */}
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
            
            {/* Right: Details */}
            <div className="flex-1 overflow-auto">
                {selectedTask ? (
                    <div className="space-y-4">
                        {/* Task Header */}
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
                        
                        {/* Summary - Markdown Rendered */}
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

function VulnerabilitiesView({ vulnerabilities }: { vulnerabilities: Vulnerability[] }) {
    const [selectedVulnerabilityId, setSelectedVulnerabilityId] = useState<number | null>(null);

    useEffect(() => {
        if (!selectedVulnerabilityId && vulnerabilities.length > 0) {
            setSelectedVulnerabilityId(vulnerabilities[0].id);
        }
    }, [selectedVulnerabilityId, vulnerabilities]);

    const selectedVulnerability = vulnerabilities.find(f => f.id === selectedVulnerabilityId);

    return (
        <div className="h-full flex gap-4">
            {/* Left: List of vulnerabilities */}
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
            
            {/* Right: Details */}
            <div className="flex-1 overflow-auto">
                {selectedVulnerability ? (
                    <div className="space-y-4">
                        {/* Header */}
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
                        
                        {/* Verification Details */}
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
                        
                        {/* Location Info */}
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

                        {/* Description */}
                        <div>
                            <h3 className="font-semibold text-sm mb-2">Description</h3>
                            <div className="prose prose-sm dark:prose-invert max-w-none p-4 border rounded-lg bg-slate-50/50 dark:bg-slate-900/20">
                                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                    {selectedVulnerability.description}
                                </ReactMarkdown>
                            </div>
                        </div>

                        {/* Evidence */}
                        {selectedVulnerability.evidence && (
                            <div>
                                <h3 className="font-semibold text-sm mb-2">Evidence / Code Snippet</h3>
                                <div className="bg-slate-900 text-slate-200 p-4 rounded-lg font-mono text-xs overflow-x-auto">
                                    <pre>{selectedVulnerability.evidence}</pre>
                                </div>
                            </div>
                        )}

                        {/* Metadata Grid */}
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

function NotesView({ notes }: { notes: Note[] }) {
    const [selectedNoteId, setSelectedNoteId] = useState<number | null>(null);

    useEffect(() => {
        if (!selectedNoteId && notes.length > 0) {
            setSelectedNoteId(notes[0].note_id);
        }
    }, [selectedNoteId, notes]);

    const selectedNote = notes.find(n => n.note_id === selectedNoteId);

    return (
        <div className="h-full flex gap-4">
            {/* Left: List of notes */}
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
            
            {/* Right: Details */}
            <div className="flex-1 overflow-auto">
                {selectedNote ? (
                    <div className="space-y-4">
                        {/* Header */}
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
                        
                        {/* Location Info */}
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

                        {/* Content */}
                        <div>
                            <h3 className="font-semibold text-sm mb-2">Content</h3>
                            <div className="prose prose-sm dark:prose-invert max-w-none p-4 border rounded-lg bg-slate-50/50 dark:bg-slate-900/20">
                                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                    {selectedNote.content}
                                </ReactMarkdown>
                            </div>
                        </div>

                        {/* Tags */}
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

export function AuditDashboard() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'plan' | 'finished' | 'live' | 'logs' | 'chat' | 'vulnerabilities' | 'notes'>('plan');
  const [manualSessionId, setManualSessionId] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [streamMessages, setStreamMessages] = useState<AuditMessage[]>([]);
  const [liveChunkContent, setLiveChunkContent] = useState<{ reasoning: string; content: string; inThinking: boolean; pending: string }>({ reasoning: '', content: '', inThinking: false, pending: '' });
  const streamRef = useRef<{ close: () => void } | null>(null);
  
  const { data: status } = useQuery({ queryKey: ['auditStatus'], queryFn: auditApi.getStatus, refetchInterval: autoRefresh ? 2000 : false });
  
  // Use new split APIs
  const { data: macroPlans } = useQuery({ queryKey: ['auditMacroPlans'], queryFn: () => auditApi.getMacroPlans(), refetchInterval: autoRefresh ? 5000 : false });
  const { data: tasks } = useQuery({ queryKey: ['auditTasks'], queryFn: () => auditApi.getTasks(), refetchInterval: autoRefresh ? 5000 : false });
  
  // Merge for compatibility with existing views
  const plans = useMemo(() => [...(macroPlans || []), ...(tasks || [])], [macroPlans, tasks]);

  const { data: logs } = useQuery({ queryKey: ['auditLogs'], queryFn: () => auditApi.getLogs(), refetchInterval: autoRefresh ? 2000 : false });
  
  const { data: sessions } = useQuery({ queryKey: ['auditSessions'], queryFn: auditApi.getSessions, refetchInterval: autoRefresh ? 3000 : false });
  const isAuditAgent = status?.current_agent === 'AUDIT_AGENT';
  
  const { data: inProgressAgentPlans } = useQuery({ 
    queryKey: ['auditTasks', 'in_progress', 'agent_task'], 
    queryFn: async () => {
      const allTasks = await auditApi.getTasks();
      return allTasks.filter((t: any) => t.status === 'in_progress' && t.task_type === 'agent_task');
    },
    enabled: isAuditAgent,
    refetchInterval: autoRefresh ? 5000 : false
  });

  const { data: completedTasks } = useQuery({ 
    queryKey: ['auditCompletedTasks'], 
    queryFn: () => auditApi.getCompletedTasks(),
    refetchInterval: autoRefresh ? 10000 : false
  });

  const currentSessionId = status?.status === 'running' ? status.current_session_id : null;
  const historySessions = sessions?.filter(session => session.session_id !== currentSessionId) || [];
  const defaultHistorySessionId = historySessions.length > 0 ? historySessions[0].session_id : null;
  const effectiveSessionId = activeTab === 'live'
    ? currentSessionId
    : (manualSessionId && manualSessionId !== currentSessionId ? manualSessionId : defaultHistorySessionId);
  const isCurrentSession = status?.current_session_id === effectiveSessionId && status?.status === 'running';

  // Load historical messages for completed sessions
  const { data: historicalMessages } = useQuery({ 
    queryKey: ['auditMessages', effectiveSessionId], 
    queryFn: () => auditApi.getMessages(effectiveSessionId || undefined), 
    enabled: !!effectiveSessionId && !isCurrentSession,
    staleTime: 0
  });

  // Setup SSE streaming for current session only if user selected the active session
  useEffect(() => {
    if (isCurrentSession && effectiveSessionId) {
      // Clear previous stream messages
      setStreamMessages([]);
      
      // Close previous stream if exists
      if (streamRef.current) {
        streamRef.current.close();
      }
      
      // Start new stream
      streamRef.current = auditApi.streamMessages(
        effectiveSessionId,
          (msg: { role?: string; content?: string; type?: string; chunk_type?: string }) => {
            // Handle raw chunk for real-time display
          if (msg.type === 'chunk') {
            const chunkContent = msg.content || '';
            
            setLiveChunkContent(prev => {
              let newReasoning = prev.reasoning;
              let newContent = prev.content;
              let inThinking = prev.inThinking;
              let pending = prev.pending + chunkContent;
              
              const TAGS = {
                OPEN: ['<think>', '&lt;think&gt;'],
                CLOSE: ['</think>', '&lt;/think&gt;']
              };

              // Helper to find first occurrence of any tag in list
              const findFirstTag = (str: string, tags: string[]) => {
                let firstIdx = -1;
                let foundTag = '';
                for (const tag of tags) {
                  const idx = str.indexOf(tag);
                  if (idx !== -1 && (firstIdx === -1 || idx < firstIdx)) {
                    firstIdx = idx;
                    foundTag = tag;
                  }
                }
                return { index: firstIdx, tag: foundTag };
              };

              // Helper to check for partial match at end of string
              const getPartialMatchLength = (str: string, tags: string[]) => {
                let maxLen = 0;
                for (const tag of tags) {
                  for (let i = 1; i < tag.length; i++) {
                    const partial = tag.slice(0, i);
                    if (str.endsWith(partial)) {
                      maxLen = Math.max(maxLen, i);
                    }
                  }
                }
                return maxLen;
              };
              
              // Process buffer loop
              while (true) {
                if (inThinking) {
                  // In thinking mode: look for closing tag
                  const { index: closeIdx, tag: closeTag } = findFirstTag(pending, TAGS.CLOSE);
                  
                  if (closeIdx !== -1) {
                    // Found closing tag
                    newReasoning += pending.slice(0, closeIdx);
                    pending = pending.slice(closeIdx + closeTag.length);
                    inThinking = false;
                    // Continue loop to process remaining buffer
                  } else {
                    // No closing tag found yet
                    // Check for partial closing tag at the end to avoid splitting it
                    const partialLen = getPartialMatchLength(pending, TAGS.CLOSE);
                    
                    if (partialLen > 0) {
                      // Append safe part to reasoning, keep partial match in pending
                      newReasoning += pending.slice(0, pending.length - partialLen);
                      pending = pending.slice(pending.length - partialLen);
                    } else {
                      // No partial match, safe to append all
                      newReasoning += pending;
                      pending = '';
                    }
                    break; // Wait for more data
                  }
                } else {
                  // Not in thinking mode: look for opening tag
                  const { index: openIdx, tag: openTag } = findFirstTag(pending, TAGS.OPEN);
                  
                  if (openIdx !== -1) {
                    // Found opening tag
                    newContent += pending.slice(0, openIdx);
                    pending = pending.slice(openIdx + openTag.length);
                    inThinking = true;
                    // Continue loop
                  } else {
                    // No opening tag found yet
                    // Check for partial opening tag at the end
                    const partialLen = getPartialMatchLength(pending, TAGS.OPEN);
                    
                    if (partialLen > 0) {
                      // Append safe part to content, keep partial match in pending
                      newContent += pending.slice(0, pending.length - partialLen);
                      pending = pending.slice(pending.length - partialLen);
                    } else {
                      // No partial match, safe to append all
                      newContent += pending;
                      pending = '';
                    }
                    break; // Wait for more data
                  }
                }
              }
              
              return { reasoning: newReasoning, content: newContent, inThinking, pending };
            });
            return;
          }
          
          // Clear live chunk content when receiving a complete message
          setLiveChunkContent({ reasoning: '', content: '', inThinking: false, pending: '' });
          
          // Add new message to stream
          const newMsg: AuditMessage = {
            id: Date.now(),
            session_id: effectiveSessionId,
            role: (msg.role || 'assistant') as AuditMessage['role'],
            content: msg.content || '',
            timestamp: Date.now() / 1000
          };
          setStreamMessages(prev => [...prev, newMsg]);
        },
        () => {
          // Session ended
          queryClient.invalidateQueries({ queryKey: ['auditSessions'] });
          queryClient.invalidateQueries({ queryKey: ['auditStatus'] });
          setLiveChunkContent({ reasoning: '', content: '', inThinking: false, pending: '' });
        },
        (err) => {
          console.error('Stream error:', err);
        }
      );
    } else {
      // Not current session, close stream
      if (streamRef.current) {
        streamRef.current.close();
        streamRef.current = null;
      }
      setStreamMessages([]);
      setLiveChunkContent({ reasoning: '', content: '', inThinking: false, pending: '' });
    }
    
    return () => {
      if (streamRef.current) {
        streamRef.current.close();
      }
    };
  }, [isCurrentSession, effectiveSessionId, queryClient]);

  const liveMessages = isCurrentSession ? streamMessages : [];
  const historyMessages = !isCurrentSession ? historicalMessages : [];
  const activeAgentPlan = inProgressAgentPlans && inProgressAgentPlans.length > 0 ? inProgressAgentPlans[0] : null;
  const sessionTypeLabel = status?.current_agent === 'AUDIT_AGENT'
    ? 'Audit Agent'
    : status?.current_agent === 'PLAN_AGENT'
      ? 'Plan Agent'
      : status?.current_agent;
  const activePlanLabel = activeAgentPlan
    ? `${activeAgentPlan.title}${activeAgentPlan.binary_name ? ` · ${activeAgentPlan.binary_name}` : ''}`
    : null;
  const liveHeaderMeta = (
    <div className="ml-auto flex items-center gap-3 text-[10px] text-slate-500">
      {sessionTypeLabel && <span>类型: {sessionTypeLabel}</span>}
      {currentSessionId && <span>会话: {currentSessionId}</span>}
      {activePlanLabel && <span className="text-slate-400">任务: {activePlanLabel}</span>}
    </div>
  );

  useEffect(() => {
    if (activeTab !== 'live') return;
    const container = document.getElementById('live-stream-output');
    if (!container) return;
    container.scrollTop = container.scrollHeight;
  }, [activeTab, liveMessages.length, liveChunkContent.content, liveChunkContent.reasoning]);

  const { data: notes } = useQuery({ queryKey: ['auditNotes'], queryFn: () => auditApi.getNotes(), refetchInterval: autoRefresh ? 5000 : false });
  const { data: vulnerabilities } = useQuery({ queryKey: ['auditVulnerabilities'], queryFn: () => auditApi.getVulnerabilities(), refetchInterval: autoRefresh ? 5000 : false });

  const startMutation = useMutation({
    mutationFn: auditApi.start,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auditStatus'] });
    }
  });

  const stopMutation = useMutation({
    mutationFn: auditApi.stop,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auditStatus'] });
    }
  });

  const splitThinkContent = (content: string) => {
    if (typeof content !== 'string') {
      return { thinkContent: null as string | null, mainContent: String(content ?? '') };
    }
    let normalized = content
      .replaceAll('&lt;think&gt;', '<think>')
      .replaceAll('&lt;/think&gt;', '</think>');
    const openRegex = /<think\s*>/gi;
    const closeRegex = /<\/think\s*>/gi;
    const openCount = normalized.match(openRegex)?.length ?? 0;
    const closeCount = normalized.match(closeRegex)?.length ?? 0;
    if (closeCount > openCount) {
      normalized = `${'<think>'.repeat(closeCount - openCount)}${normalized}`;
    }
    let cursor = 0;
    const mainParts: string[] = [];
    const thinkParts: string[] = [];
    while (cursor < normalized.length) {
      openRegex.lastIndex = cursor;
      const openMatch = openRegex.exec(normalized);
      if (!openMatch) {
        mainParts.push(normalized.slice(cursor));
        break;
      }
      const openIndex = openMatch.index;
      mainParts.push(normalized.slice(cursor, openIndex));
      closeRegex.lastIndex = openIndex + openMatch[0].length;
      const closeMatch = closeRegex.exec(normalized);
      if (!closeMatch) {
        thinkParts.push(normalized.slice(openIndex + openMatch[0].length));
        cursor = normalized.length;
        break;
      }
      thinkParts.push(normalized.slice(openIndex + openMatch[0].length, closeMatch.index));
      cursor = closeMatch.index + closeMatch[0].length;
    }
    const mainContent = mainParts.join('');
    const thinkContent = thinkParts.length ? thinkParts.join('\n\n') : null;
    return { thinkContent, mainContent };
  };

  const renderOutput = (messageList: AuditMessage[] | undefined, title: string, headerMeta?: React.ReactNode, scrollId?: string, liveChunk?: { reasoning: string; content: string; inThinking: boolean }) => {
    const visibleMessages = (messageList || []).filter(m => m.role === 'assistant' || m.role === 'tool_call' || m.role === 'tool_result');
    const hasLiveChunk = liveChunk && (liveChunk.reasoning || liveChunk.content);
    return (
      <div className="h-full bg-black rounded-lg overflow-hidden border border-slate-800 font-mono text-sm">
        <div className="flex items-center gap-2 px-3 py-2 border-b border-slate-800 bg-slate-900/50">
          <div className="w-3 h-3 rounded-full bg-red-500/80" />
          <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
          <div className="w-3 h-3 rounded-full bg-green-500/80" />
          <span className="ml-2 text-xs text-slate-500">{title}</span>
          {headerMeta}
        </div>
        <div id={scrollId} className="h-[calc(100%-40px)] overflow-auto p-4 text-slate-300">
          {visibleMessages.map((msg) => {
            if (msg.role === 'tool_call') {
              let toolCallData;
              try {
                toolCallData = JSON.parse(msg.content);
              } catch {
                toolCallData = { name: 'unknown', arguments: msg.content };
              }
              let args: Record<string, unknown> = {};
              if (typeof toolCallData.arguments === 'string') {
                try {
                  args = JSON.parse(toolCallData.arguments);
                } catch {
                  args = { _raw: toolCallData.arguments };
                }
              } else if (typeof toolCallData.arguments === 'object' && toolCallData.arguments !== null) {
                args = toolCallData.arguments as Record<string, unknown>;
              }
              const formatValue = (val: unknown): string => {
                if (val === null || val === undefined) return 'null';
                if (typeof val === 'object') {
                  const str = JSON.stringify(val);
                  return str.length > 50 ? str.slice(0, 50) + '...' : str;
                }
                const str = String(val);
                return str.length > 50 ? str.slice(0, 50) + '...' : str;
              };
              const argStr = Object.entries(args)
                .map(([k, v]) => `${k}=${formatValue(v)}`)
                .join(', ');
              return (
                <div key={msg.id} className="mb-3">
                  <div className="flex items-center gap-2 text-cyan-400">
                    <span className="text-purple-400">➜</span>
                    <span className="text-cyan-400 font-semibold">{toolCallData.name}({argStr})</span>
                  </div>
                </div>
              );
            }
            if (msg.role === 'tool_result') {
              return (
                <details key={msg.id} className="mb-3 ml-4 pl-3 border-l border-slate-700">
                  <summary className="cursor-pointer text-[10px] text-green-500/70 mb-1 select-none hover:text-green-500">
                    ← Result (click to expand)
                  </summary>
                  <div className="text-slate-400 text-xs max-h-32 overflow-auto mt-1">
                    <pre className="whitespace-pre-wrap">{msg.content}</pre>
                  </div>
                </details>
              );
            }
            const { thinkContent, mainContent } = splitThinkContent(msg.content);
            return (
              <div key={msg.id} className="mb-4">
                {thinkContent && (
                  <details className="mb-2 rounded border border-slate-800/70 bg-slate-900/40 px-2 py-1" open>
                    <summary className="cursor-pointer text-slate-400 text-xs hover:text-slate-300 mb-1 select-none">
                      ⟪ thinking
                    </summary>
                    <div className="pl-2 pb-1 text-slate-400 text-xs whitespace-pre-wrap">
                      {thinkContent}
                    </div>
                  </details>
                )}
                {mainContent && mainContent.trim() && (
                  <div className="prose prose-sm prose-invert max-w-none break-words
                      prose-p:leading-relaxed prose-pre:bg-slate-800 prose-pre:p-2 prose-pre:rounded
                      prose-code:text-amber-300 prose-code:bg-slate-800/50 prose-code:px-1 prose-code:rounded before:prose-code:content-none after:prose-code:content-none">
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                      {mainContent}
                    </ReactMarkdown>
                  </div>
                )}
              </div>
            );
          })}
          {/* Live chunk display - real-time streaming content */}
          {hasLiveChunk && (
            <div className="mb-4">
              {(liveChunk.reasoning || liveChunk.inThinking) && (
                <details className="mb-2 rounded border border-slate-800/70 bg-slate-900/40 px-2 py-1" open={true}>
                  <summary className="cursor-pointer text-slate-400 text-xs hover:text-slate-300 mb-1 select-none">
                    ⟪ thinking {liveChunk.inThinking ? '(streaming...)' : ''}
                  </summary>
                  <div className="pl-2 pb-1 text-slate-400 text-xs whitespace-pre-wrap">
                    {liveChunk.reasoning}
                  </div>
                </details>
              )}
              {liveChunk.content && (
                <div className="prose prose-sm prose-invert max-w-none break-words text-amber-300
                    prose-p:leading-relaxed prose-pre:bg-slate-800 prose-pre:p-2 prose-pre:rounded
                    prose-code:text-amber-300 prose-code:bg-slate-800/50 prose-code:px-1 prose-code:rounded before:prose-code:content-none after:prose-code:content-none">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {liveChunk.content}
                  </ReactMarkdown>
                </div>
              )}
            </div>
          )}
          {visibleMessages.length === 0 && !hasLiveChunk && (
            <div className="flex flex-col items-center justify-center h-full text-slate-600">
              <Terminal className="w-12 h-12 mb-4 opacity-20" />
              <p>No model output yet.</p>
            </div>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="container mx-auto p-4 md:p-6 h-[calc(100vh-60px)] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-6 shrink-0">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">AIDA Audit Dashboard</h1>
          <p className="text-sm text-muted-foreground">Monitor and control the autonomous auditing agent.</p>
        </div>
        
        <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
                <label className="text-xs text-muted-foreground font-medium">Auto-Refresh</label>
                <button 
                    onClick={() => setAutoRefresh(!autoRefresh)}
                    className={`w-8 h-4 rounded-full transition-colors relative ${autoRefresh ? 'bg-green-500' : 'bg-slate-300'}`}
                >
                    <div className={`absolute top-0.5 w-3 h-3 bg-white rounded-full transition-transform ${autoRefresh ? 'left-4.5 translate-x-4' : 'left-0.5'}`} />
                </button>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-50 dark:bg-slate-900 rounded-md border">
                <span className="text-xs text-muted-foreground uppercase font-bold tracking-wider">Status</span>
                <div className={`w-2 h-2 rounded-full ${status?.status === 'running' ? 'bg-green-500 animate-pulse' : status?.status === 'failed' ? 'bg-red-500' : 'bg-slate-300'}`} />
                <span className="text-sm font-medium">{status?.status?.toUpperCase() || 'UNKNOWN'}</span>
                {status?.current_agent && (
                    <>
                        <div className="w-px h-3 bg-border mx-1" />
                        <span className="text-xs text-muted-foreground">Agent:</span>
                        <span className="text-sm font-medium text-blue-600 dark:text-blue-400">{status.current_agent}</span>
                    </>
                )}
            </div>
            
            {status?.status === 'running' ? (
                <Button variant="destructive" size="sm" onClick={() => stopMutation.mutate()} disabled={stopMutation.isPending} className="gap-2">
                    <Square className="w-4 h-4" fill="currentColor" /> Stop Audit
                </Button>
            ) : (
                <Button size="sm" onClick={() => startMutation.mutate()} disabled={startMutation.isPending} className="gap-2">
                    <Play className="w-4 h-4" fill="currentColor" /> Start Audit
                </Button>
            )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b mb-4 shrink-0 overflow-x-auto">
        <button 
          onClick={() => setActiveTab('plan')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'plan' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <ListTodo className="w-4 h-4" /> Plan
        </button>
        <button 
          onClick={() => setActiveTab('finished')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'finished' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <CheckCircle2 className="w-4 h-4" /> Finished
        </button>
        <button 
          onClick={() => setActiveTab('vulnerabilities')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'vulnerabilities' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <AlertTriangle className="w-4 h-4" /> Vulnerabilities
        </button>
        <button 
          onClick={() => setActiveTab('notes')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'notes' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <StickyNote className="w-4 h-4" /> Notes
        </button>
        <button 
          onClick={() => setActiveTab('chat')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'chat' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <MessageSquare className="w-4 h-4" /> Chat History
        </button>
        <button 
          onClick={() => setActiveTab('live')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'live' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <Circle className="w-4 h-4" /> Live Stream
        </button>
        <button 
          onClick={() => setActiveTab('logs')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'logs' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <Terminal className="w-4 h-4" /> Live Logs
        </button>
      </div>

      {/* Content Area */}
      <div className="flex-1 min-h-0 overflow-hidden">
        {activeTab === 'plan' && (
          <Card className="h-full flex flex-col border-0 shadow-none bg-transparent">
            <CardContent className="flex-1 overflow-auto p-0 pr-2">
               <PlanView plans={plans || []} />
            </CardContent>
          </Card>
        )}

        {activeTab === 'finished' && (
          <Card className="h-full flex flex-col border-0 shadow-none bg-transparent">
            <CardContent className="flex-1 overflow-auto p-0">
               {completedTasks && completedTasks.length > 0 ? (
                  <FinishedPlansView completedTasks={completedTasks} />
               ) : (
                  <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                    <CheckCircle2 className="w-12 h-12 mb-4 opacity-20" />
                    <p>No completed tasks yet.</p>
                    <p className="text-xs mt-2">Complete an audit task to see results here.</p>
                  </div>
               )}
            </CardContent>
          </Card>
        )}

        {activeTab === 'live' && (
          <div className="h-full">
            {status?.status === 'running' && status?.current_session_id ? (
              renderOutput(liveMessages, 'Live Stream', liveHeaderMeta, 'live-stream-output', liveChunkContent)
            ) : (
              <div className="h-full flex items-center justify-center text-muted-foreground">
                <div className="text-center">
                  <Terminal className="w-12 h-12 mb-4 opacity-20 mx-auto" />
                  <p>No live session running.</p>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'chat' && (
          <div className="h-full flex gap-4">
              <div className="w-64 border-r pr-2 overflow-auto hidden md:block">
                  <div className="text-xs font-semibold text-muted-foreground uppercase mb-2 px-2">History</div>
                  <div className="space-y-1">
                      {historySessions.map((session) => (
                          <button
                              key={session.session_id}
                              onClick={() => setManualSessionId(session.session_id)}
                              className={`w-full text-left px-3 py-2 rounded-md text-xs truncate transition-colors ${effectiveSessionId === session.session_id ? 'bg-slate-100 dark:bg-slate-800 font-medium' : 'hover:bg-slate-50 dark:hover:bg-slate-900 text-muted-foreground'}`}
                          >
                              <div className="flex items-center justify-between mb-1">
                                  <span className="capitalize">{session.session_id.split('-')[0]}</span>
                                  <span className="text-[10px] opacity-70">{session.message_count} msgs</span>
                              </div>
                              <div className="text-[10px] opacity-50">{new Date(session.start_time * 1000).toLocaleString()}</div>
                          </button>
                      ))}
                      {(!sessions?.length || historySessions.length === 0) && (
                          <div className="text-xs text-muted-foreground px-2 italic">
                              {status?.status === 'running' ? 'Live session in progress' : 'No completed sessions'}
                          </div>
                      )}
                  </div>
              </div>

              <div className="flex-1 min-h-0">
                {renderOutput(historyMessages, 'Chat History')}
              </div>
          </div>
        )}
        
        {activeTab === 'vulnerabilities' && (
          <Card className="h-full flex flex-col border-0 shadow-none bg-transparent">
            <CardContent className="flex-1 overflow-auto p-0">
               {vulnerabilities && vulnerabilities.length > 0 ? (
                   <VulnerabilitiesView vulnerabilities={vulnerabilities} />
               ) : (
                  <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                    <AlertTriangle className="w-12 h-12 mb-4 opacity-20" />
                    <p>No security vulnerabilities yet.</p>
                  </div>
               )}
            </CardContent>
          </Card>
        )}

        {activeTab === 'notes' && (
          <Card className="h-full flex flex-col border-0 shadow-none bg-transparent">
            <CardContent className="flex-1 overflow-auto p-0">
                {notes && notes.length > 0 ? (
                    <NotesView notes={notes} />
                ) : (
                    <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                        <StickyNote className="w-12 h-12 mb-4 opacity-20" />
                        <p>No analysis notes yet.</p>
                    </div>
                )}
            </CardContent>
          </Card>
        )}

        {activeTab === 'logs' && (
          <Card className="h-full flex flex-col border-0 shadow-none bg-transparent">
            <CardContent className="flex-1 bg-black rounded-lg p-0 overflow-hidden border border-slate-800">
               <div className="h-full overflow-auto p-4 font-mono text-xs text-green-400 space-y-1">
               {[...(logs || [])].reverse().map((log) => (
                 <div key={log.id} className="break-all hover:bg-white/5 px-1 rounded">
                   <span className="opacity-50 mr-3 text-blue-400">[{new Date(log.timestamp * 1000).toLocaleTimeString()}]</span>
                   {log.message}
                 </div>
               ))}
               {!logs?.length && (
                   <div className="flex flex-col items-center justify-center h-full text-slate-600">
                       <Terminal className="w-12 h-12 mb-4 opacity-20" />
                       <p>Waiting for logs...</p>
                   </div>
               )}
               </div>
            </CardContent>
           </Card>
        )}
      </div>
    </div>
  );
}
