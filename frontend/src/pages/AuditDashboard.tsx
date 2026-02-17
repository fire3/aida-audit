import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { auditApi, type AuditPlan, type AuditMessage } from '../api/client';
import { Card, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { useState, useMemo, useEffect, useRef } from 'react';
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
  Code,
  Archive
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
  const [activeTab, setActiveTab] = useState<'plan' | 'live' | 'logs' | 'chat' | 'findings' | 'notes'>('plan');
  const [manualSessionId, setManualSessionId] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [streamMessages, setStreamMessages] = useState<AuditMessage[]>([]);
  const streamRef = useRef<{ close: () => void } | null>(null);
  
  const { data: status } = useQuery({ queryKey: ['auditStatus'], queryFn: auditApi.getStatus, refetchInterval: autoRefresh ? 2000 : false });
  const { data: plans } = useQuery({ queryKey: ['auditPlans'], queryFn: () => auditApi.getPlans(), refetchInterval: autoRefresh ? 5000 : false });
  const { data: logs } = useQuery({ queryKey: ['auditLogs'], queryFn: () => auditApi.getLogs(), refetchInterval: autoRefresh ? 2000 : false });
  
  const { data: sessions } = useQuery({ queryKey: ['auditSessions'], queryFn: auditApi.getSessions, refetchInterval: autoRefresh ? 3000 : false });
  const isAuditAgent = status?.current_agent === 'AUDIT_AGENT';
  const { data: inProgressAgentPlans } = useQuery({ 
    queryKey: ['auditPlans', 'in_progress', 'agent_plan'], 
    queryFn: () => auditApi.getPlans('in_progress', 'agent_plan'),
    enabled: isAuditAgent,
    refetchInterval: autoRefresh ? 5000 : false
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
        (msg) => {
          console.log('SSE received:', msg);
          // Add new message to stream
          const newMsg: AuditMessage = {
            id: Date.now(),
            session_id: effectiveSessionId,
            role: msg.role as AuditMessage['role'],
            content: msg.content,
            timestamp: Date.now() / 1000
          };
          setStreamMessages(prev => [...prev, newMsg]);
        },
        () => {
          // Session ended
          console.log('Session stream ended');
          queryClient.invalidateQueries({ queryKey: ['auditSessions'] });
          queryClient.invalidateQueries({ queryKey: ['auditStatus'] });
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
    }
    
    return () => {
      if (streamRef.current) {
        streamRef.current.close();
      }
    };
  }, [isCurrentSession, effectiveSessionId, queryClient]);

  const liveMessages = isCurrentSession ? streamMessages : [];
  const historyMessages = !isCurrentSession ? historicalMessages : [];
  const lastLiveMessage = liveMessages.length ? liveMessages[liveMessages.length - 1] : null;
  const lastHistoryMessage = historyMessages && historyMessages.length ? historyMessages[historyMessages.length - 1] : null;
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
  }, [activeTab, liveMessages.length]);

  useEffect(() => {
    if (!lastLiveMessage) return;
    const content = typeof lastLiveMessage.content === 'string' ? lastLiveMessage.content : String(lastLiveMessage.content ?? '');
    const hasThinkTag = /<think\s*>/i.test(content) || /<\/think\s*>/i.test(content);
    const hasEscapedThink = /&lt;think&gt;/i.test(content) || /&lt;\/think&gt;/i.test(content);
    console.log('LiveStream think check:', {
      sessionId: lastLiveMessage.session_id,
      role: lastLiveMessage.role,
      hasThinkTag,
      hasEscapedThink,
      preview: content.slice(0, 200)
    });
  }, [lastLiveMessage]);

  useEffect(() => {
    if (!lastHistoryMessage) return;
    const content = typeof lastHistoryMessage.content === 'string' ? lastHistoryMessage.content : String(lastHistoryMessage.content ?? '');
    const hasThinkTag = /<think\s*>/i.test(content) || /<\/think\s*>/i.test(content);
    const hasEscapedThink = /&lt;think&gt;/i.test(content) || /&lt;\/think&gt;/i.test(content);
    console.log('ChatHistory think check:', {
      sessionId: lastHistoryMessage.session_id,
      role: lastHistoryMessage.role,
      hasThinkTag,
      hasEscapedThink,
      preview: content.slice(0, 200)
    });
  }, [lastHistoryMessage]);

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

  const renderOutput = (messageList: AuditMessage[] | undefined, title: string, headerMeta?: React.ReactNode, scrollId?: string) => {
    const visibleMessages = (messageList || []).filter(m => m.role === 'assistant' || m.role === 'tool_call' || m.role === 'tool_result');
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
                  <div className="whitespace-pre-wrap leading-relaxed">
                    {mainContent}
                  </div>
                )}
              </div>
            );
          })}
          {visibleMessages.length === 0 && (
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
          onClick={() => setActiveTab('live')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'live' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <Circle className="w-4 h-4" /> Live Stream
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

        {activeTab === 'live' && (
          <div className="h-full">
            {status?.status === 'running' && status?.current_session_id ? (
              renderOutput(liveMessages, 'Live Stream', liveHeaderMeta, 'live-stream-output')
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
