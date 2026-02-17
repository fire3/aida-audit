import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { auditApi, type AuditPlan } from '../api/client';
import { Card, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { useState, useMemo, useEffect } from 'react';
import {
  CheckCircle2, 
  Circle, 
  Clock, 
  AlertCircle, 
  ChevronRight, 
  Terminal, 
  MessageSquare, 
  ListTodo,
  Play,
  Square,
  StickyNote,
  AlertTriangle,
  Code
} from 'lucide-react';
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

function PlanView({ plans }: { plans: AuditPlan[] }) {
    const macroPlans = useMemo(() => plans.filter(p => p.plan_type === 'audit_plan'), [plans]);
    const agentTasks = useMemo(() => plans.filter(p => p.plan_type === 'agent_plan'), [plans]);

    return (
        <div className="h-full flex gap-4">
            {/* Macro Plans (Left) */}
            <div className="w-1/3 border-r pr-4 overflow-auto">
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
                            
                            {/* Associated Agent Tasks */}
                            <div className="space-y-1 mt-3 pl-2 border-l-2 border-slate-200 dark:border-slate-800">
                                <div className="text-[10px] uppercase font-bold text-muted-foreground mb-1">Execution Tasks</div>
                                {agentTasks.filter(t => t.parent_id === plan.id).map(task => (
                                    <div key={task.id} className="flex items-center gap-2 text-xs py-1">
                                        <StatusIcon status={task.status} />
                                        <span className={`${task.status === 'completed' ? 'line-through text-muted-foreground' : ''}`}>
                                            {task.title}
                                        </span>
                                    </div>
                                ))}
                                {agentTasks.filter(t => t.parent_id === plan.id).length === 0 && (
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

            {/* All Agent Tasks (Right/Detail) - or maybe just a list of recent activity? */}
            <div className="flex-1 overflow-auto">
                 <h3 className="font-semibold mb-4 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-orange-500" />
                    Task Execution Stream
                </h3>
                <div className="space-y-2">
                    {agentTasks.sort((a,b) => b.updated_at - a.updated_at).map(task => (
                         <div key={task.id} className="flex items-center gap-3 p-2 border rounded hover:bg-slate-50 dark:hover:bg-slate-800/50">
                            <StatusIcon status={task.status} />
                            <div className="flex-1">
                                <div className="text-sm font-medium">{task.title}</div>
                                {task.binary_name && (
                                    <div className="text-xs font-mono text-purple-600 dark:text-purple-400 mb-0.5">
                                        Target: {task.binary_name}
                                    </div>
                                )}
                                <div className="text-xs text-muted-foreground flex items-center gap-2">
                                    <span>ID: {task.id}</span>
                                    <span>•</span>
                                    <span>Parent: {macroPlans.find(p => p.id === task.parent_id)?.title || 'Unknown'}</span>
                                    <span>•</span>
                                    <span>Updated: {new Date(task.updated_at * 1000).toLocaleString()}</span>
                                </div>
                                {task.summary && (
                                    <div className="mt-2 text-xs bg-slate-100 dark:bg-slate-900 p-2 rounded text-muted-foreground border-l-2 border-green-500">
                                        <div className="font-semibold text-[10px] uppercase mb-1 text-green-600 dark:text-green-400">Task Summary</div>
                                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{task.summary}</ReactMarkdown>
                                    </div>
                                )}
                            </div>
                            <Badge variant={task.status === 'completed' ? 'default' : task.status === 'in_progress' ? 'secondary' : task.status === 'failed' ? 'destructive' : 'outline'}>
                                {task.status}
                            </Badge>
                         </div>
                    ))}
                </div>
            </div>
        </div>
    );
}

export function AuditDashboard() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'plan' | 'logs' | 'chat' | 'findings' | 'notes'>('plan');
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  
  const { data: status } = useQuery({ queryKey: ['auditStatus'], queryFn: auditApi.getStatus, refetchInterval: autoRefresh ? 2000 : false });
  const { data: plans } = useQuery({ queryKey: ['auditPlans'], queryFn: () => auditApi.getPlans(), refetchInterval: autoRefresh ? 5000 : false });
  const { data: logs } = useQuery({ queryKey: ['auditLogs'], queryFn: () => auditApi.getLogs(), refetchInterval: autoRefresh ? 2000 : false });
  
  const { data: sessions } = useQuery({ queryKey: ['auditSessions'], queryFn: auditApi.getSessions, refetchInterval: autoRefresh ? 10000 : false });

  // Select latest session only if none selected
  useEffect(() => {
      if (sessions && sessions.length > 0 && !selectedSession) {
          const latestSession = sessions[0].session_id;
          setSelectedSession(latestSession);
      }
  }, [sessions, selectedSession]);

  const { data: messages } = useQuery({ 
    queryKey: ['auditMessages', selectedSession, status?.current_session_id], 
    queryFn: () => auditApi.getMessages(selectedSession || undefined), 
    refetchInterval: autoRefresh ? 2000 : false,
    enabled: !!selectedSession
  });

  const { data: notes } = useQuery({ queryKey: ['auditNotes'], queryFn: () => auditApi.getNotes(), refetchInterval: autoRefresh ? 5000 : false });
  const { data: findings } = useQuery({ queryKey: ['auditFindings'], queryFn: () => auditApi.getFindings(), refetchInterval: autoRefresh ? 5000 : false });

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

  return (
    <div className="container mx-auto p-4 md:p-6 h-[calc(100vh-60px)] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-6 shrink-0">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Automated Audit Dashboard</h1>
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
          onClick={() => setActiveTab('chat')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'chat' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <MessageSquare className="w-4 h-4" /> Chat History
        </button>
        <button 
          onClick={() => setActiveTab('findings')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'findings' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <AlertTriangle className="w-4 h-4" /> Findings
        </button>
        <button 
          onClick={() => setActiveTab('notes')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'notes' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <StickyNote className="w-4 h-4" /> Notes
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
               {plans && plans.length > 0 ? (
                   <PlanView plans={plans} />
               ) : (
                  <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                    <ListTodo className="w-12 h-12 mb-4 opacity-20" />
                    <p>No audit plans found.</p>
                    <p className="text-xs mt-2">Start the audit to generate an analysis plan.</p>
                  </div>
               )}
            </CardContent>
          </Card>
        )}

        {activeTab === 'chat' && (
          <div className="h-full flex gap-4">
              {/* Session List */}
              <div className="w-64 border-r pr-2 overflow-auto hidden md:block">
                  <div className="text-xs font-semibold text-muted-foreground uppercase mb-2 px-2">Sessions</div>
                  <div className="space-y-1">
                      {sessions?.map((session) => (
                          <button
                              key={session.session_id}
                              onClick={() => setSelectedSession(session.session_id)}
                              className={`w-full text-left px-3 py-2 rounded-md text-xs truncate transition-colors ${selectedSession === session.session_id ? 'bg-slate-100 dark:bg-slate-800 font-medium' : 'hover:bg-slate-50 dark:hover:bg-slate-900 text-muted-foreground'}`}
                          >
                              <div className="flex items-center justify-between mb-1">
                                  <span className="capitalize">{session.session_id.split('-')[0]}</span>
                                  <span className="text-[10px] opacity-70">{session.message_count} msgs</span>
                              </div>
                              <div className="text-[10px] opacity-50">{new Date(session.start_time * 1000).toLocaleString()}</div>
                          </button>
                      ))}
                      {!sessions?.length && <div className="text-xs text-muted-foreground px-2 italic">No sessions recorded.</div>}
                  </div>
              </div>

              {/* OpenCode-style Terminal Output */}
              <div className="flex-1 min-h-0">
                  <div className="h-full bg-black rounded-lg overflow-hidden border border-slate-800 font-mono text-sm">
                      <div className="flex items-center gap-2 px-3 py-2 border-b border-slate-800 bg-slate-900/50">
                          <div className="w-3 h-3 rounded-full bg-red-500/80" />
                          <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                          <div className="w-3 h-3 rounded-full bg-green-500/80" />
                          <span className="ml-2 text-xs text-slate-500">Audit Output</span>
                      </div>
                      <div className="h-[calc(100%-40px)] overflow-auto p-4 text-slate-300">
                          {messages?.filter(m => m.role === 'assistant' || m.role === 'tool_call' || m.role === 'tool_result').map((msg) => {
                              if (msg.role === 'tool_call') {
                                  let toolCallData;
                                  try {
                                      toolCallData = JSON.parse(msg.content);
                                  } catch {
                                      toolCallData = { name: 'unknown', arguments: msg.content };
                                  }
                                  const args = toolCallData.arguments || {};
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
                              // assistant message
                              const thinkMatch = msg.content && typeof msg.content === 'string' ? msg.content.match(/<think>([\s\S]*?)<\/think>/) : null;
                              let thinkContent = thinkMatch ? thinkMatch[1] : null;
                              let mainContent = msg.content && typeof msg.content === 'string' ? msg.content.replace(/<think>[\s\S]*?<\/think>/, '') : msg.content;
                              
                              return (
                                  <div key={msg.id} className="mb-4">
                                      {thinkContent && (
                                          <details className="mb-2" open>
                                              <summary className="cursor-pointer text-slate-500 text-xs hover:text-slate-400 mb-1 select-none">
                                                  ⟪ thinking
                                              </summary>
                                              <div className="pl-3 text-slate-500 text-xs whitespace-pre-wrap">
                                                  {thinkContent}
                                              </div>
                                          </details>
                                      )}
                                      {mainContent && mainContent.trim() && (
                                          <div className="whitespace-pre-wrap leading-relaxed">
                                              {mainContent}
                                          </div>
                                      )}
                                  </div>
                              );
                          })}
                          {(!messages?.filter(m => m.role === 'assistant' || m.role === 'tool_call' || m.role === 'tool_result').length) && (
                              <div className="flex flex-col items-center justify-center h-full text-slate-600">
                                  <Terminal className="w-12 h-12 mb-4 opacity-20" />
                                  <p>No model output yet.</p>
                              </div>
                          )}
                      </div>
                  </div>
              </div>
          </div>
        )}
        
        {activeTab === 'findings' && (
          <div className="h-full overflow-auto p-4">
              <Card className="flex flex-col h-fit">
                  <div className="p-4 border-b bg-slate-50 dark:bg-slate-900/50 font-semibold flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-red-500" /> Security Findings
                  </div>
                  <CardContent className="p-4">
                      {findings && findings.length > 0 ? (
                          <div className="space-y-4">
                              {findings.map(finding => (
                                  <div key={finding.finding_id} className="border rounded-lg p-3 shadow-sm hover:shadow-md transition-shadow cursor-pointer">
                                      <details className="group">
                                          <summary className="flex items-center justify-between mb-2 list-none outline-none">
                                             <div className="flex items-center gap-2">
                                                 <ChevronRight className="w-4 h-4 transition-transform group-open:rotate-90 text-muted-foreground" />
                                                 <div className="font-semibold text-sm">{finding.category}</div>
                                             </div>
                                             <Badge variant={finding.severity === 'critical' ? 'destructive' : finding.severity === 'high' ? 'destructive' : finding.severity === 'medium' ? 'warning' : 'info'}>
                                                  {finding.severity}
                                              </Badge>
                                          </summary>
                                          <div className="pl-6 text-sm text-muted-foreground mt-2 space-y-2">
                                              <p>{finding.description}</p>
                                              {finding.evidence && (
                                                  <div className="bg-slate-100 dark:bg-slate-800 p-2 rounded text-xs font-mono whitespace-pre-wrap">
                                                      {finding.evidence}
                                                  </div>
                                              )}
                                              {finding.function_name && (
                                                  <div className="flex items-center gap-2 text-xs font-mono bg-slate-100 dark:bg-slate-800 p-1 rounded w-fit">
                                                      <Code className="w-3 h-3" />
                                                      {finding.function_name} @ {finding.address}
                                                  </div>
                                              )}
                                              <div className="text-[10px] text-muted-foreground pt-2 border-t mt-2">
                                                  Found at: {new Date(finding.created_at).toLocaleString()}
                                              </div>
                                          </div>
                                      </details>
                                  </div>
                              ))}
                          </div>
                      ) : (
                          <div className="flex flex-col items-center justify-center py-10 text-muted-foreground">
                              <p>No security findings yet.</p>
                          </div>
                      )}
                  </CardContent>
              </Card>
          </div>
        )}

        {activeTab === 'notes' && (
          <div className="h-full overflow-auto p-4">
              <Card className="flex flex-col h-fit">
                  <div className="p-4 border-b bg-slate-50 dark:bg-slate-900/50 font-semibold flex items-center gap-2">
                      <StickyNote className="w-4 h-4 text-blue-500" /> Analysis Notes
                  </div>
                  <CardContent className="p-4">
                      {notes && notes.length > 0 ? (
                          <div className="space-y-4">
                              {notes.map(note => (
                                  <div key={note.note_id} className="border rounded-lg p-3 shadow-sm bg-yellow-50/50 dark:bg-yellow-900/10 hover:shadow-md transition-shadow cursor-pointer">
                                      <details className="group">
                                          <summary className="flex items-center justify-between mb-2 list-none outline-none">
                                              <div className="flex items-center gap-2">
                                                 <ChevronRight className="w-4 h-4 transition-transform group-open:rotate-90 text-muted-foreground" />
                                                 <div className="font-semibold text-xs text-muted-foreground uppercase">{note.note_type}</div>
                                              </div>
                                              <span className="text-[10px] text-muted-foreground">{new Date(note.created_at).toLocaleString()}</span>
                                          </summary>
                                          <div className="pl-6 text-sm mt-2 prose prose-sm dark:prose-invert max-w-none">
                                              <ReactMarkdown remarkPlugins={[remarkGfm]}>{note.content}</ReactMarkdown>
                                          </div>
                                          {note.tags && note.tags.length > 0 && (
                                              <div className="flex flex-wrap gap-1 mt-2 pl-6">
                                                  {note.tags.map(tag => (
                                                      <span key={tag} className="text-[10px] bg-slate-200 dark:bg-slate-700 px-1.5 py-0.5 rounded text-slate-700 dark:text-slate-300">#{tag}</span>
                                                  ))}
                                              </div>
                                          )}
                                      </details>
                                  </div>
                              ))}
                          </div>
                      ) : (
                          <div className="flex flex-col items-center justify-center py-10 text-muted-foreground">
                              <p>No analysis notes yet.</p>
                          </div>
                      )}
                  </CardContent>
              </Card>
          </div>
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
