import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { auditApi, type AuditMessage } from '../api/client';
import { Card, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { useState, useMemo, useEffect, useRef } from 'react';
import {
  CheckCircle2,
  Circle,
  Terminal,
  MessageSquare,
  ListTodo,
  Play,
  Square,
  StickyNote,
  AlertTriangle,
  Layers
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { PlanView } from '../components/PlanView';
import { FinishedPlansView } from '../components/FinishedPlansView';
import { VulnerabilitiesView } from '../components/VulnerabilitiesView';
import { NotesView } from '../components/NotesView';
import { CoverageView } from '../components/CoverageView';

export function AuditDashboard() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'plan' | 'finished' | 'live' | 'logs' | 'chat' | 'vulnerabilities' | 'notes' | 'coverage'>('plan');
  const [manualSessionId, setManualSessionId] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [streamMessages, setStreamMessages] = useState<AuditMessage[]>([]);
  const [liveChunkContent, setLiveChunkContent] = useState<{ reasoning: string; content: string; inThinking: boolean; pending: string }>({ reasoning: '', content: '', inThinking: false, pending: '' });
  const streamRef = useRef<{ close: () => void } | null>(null);
  
  const { data: status } = useQuery({ queryKey: ['auditStatus'], queryFn: auditApi.getStatus, refetchInterval: autoRefresh ? 2000 : false });
  
  const { data: macroPlans } = useQuery({ queryKey: ['auditMacroPlans'], queryFn: () => auditApi.getMacroPlans(), refetchInterval: autoRefresh ? 5000 : false });
  const { data: tasks } = useQuery({ queryKey: ['auditTasks'], queryFn: () => auditApi.getTasks(), refetchInterval: autoRefresh ? 5000 : false });

  const plans = useMemo(() => [...(macroPlans || []), ...(tasks || [])], [macroPlans, tasks]);

  const { data: logs } = useQuery({ queryKey: ['auditLogs'], queryFn: () => auditApi.getLogs(), refetchInterval: autoRefresh ? 2000 : false });
  
  const { data: sessions } = useQuery({ queryKey: ['auditSessions'], queryFn: auditApi.getSessions, refetchInterval: autoRefresh ? 3000 : false });
  const isAuditAgent = status?.current_agent === 'AUDIT_AGENT';
  
  const { data: inProgressAgentPlans } = useQuery({ 
    queryKey: ['auditTasks', 'in_progress', 'ANALYSIS'], 
    queryFn: async () => {
      const allTasks = await auditApi.getTasks();
      return allTasks.filter((t: any) => t.status === 'in_progress' && t.task_type === 'ANALYSIS');
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

  const { data: historicalMessages } = useQuery({ 
    queryKey: ['auditMessages', effectiveSessionId], 
    queryFn: () => auditApi.getMessages(effectiveSessionId || undefined), 
    enabled: !!effectiveSessionId && !isCurrentSession,
    staleTime: 0
  });

  useEffect(() => {
    if (isCurrentSession && effectiveSessionId) {
      setStreamMessages([]);
      
      if (streamRef.current) {
        streamRef.current.close();
      }
      
      streamRef.current = auditApi.streamMessages(
        effectiveSessionId,
          (msg: { role?: string; content?: string; type?: string; chunk_type?: string }) => {
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
              
              while (true) {
                if (inThinking) {
                  const { index: closeIdx, tag: closeTag } = findFirstTag(pending, TAGS.CLOSE);
                  
                  if (closeIdx !== -1) {
                    newReasoning += pending.slice(0, closeIdx);
                    pending = pending.slice(closeIdx + closeTag.length);
                    inThinking = false;
                  } else {
                    const partialLen = getPartialMatchLength(pending, TAGS.CLOSE);
                    
                    if (partialLen > 0) {
                      newReasoning += pending.slice(0, pending.length - partialLen);
                      pending = pending.slice(pending.length - partialLen);
                    } else {
                      newReasoning += pending;
                      pending = '';
                    }
                    break;
                  }
                } else {
                  const { index: openIdx, tag: openTag } = findFirstTag(pending, TAGS.OPEN);
                  
                  if (openIdx !== -1) {
                    newContent += pending.slice(0, openIdx);
                    pending = pending.slice(openIdx + openTag.length);
                    inThinking = true;
                  } else {
                    const partialLen = getPartialMatchLength(pending, TAGS.OPEN);
                    
                    if (partialLen > 0) {
                      newContent += pending.slice(0, pending.length - partialLen);
                      pending = pending.slice(pending.length - partialLen);
                    } else {
                      newContent += pending;
                      pending = '';
                    }
                    break;
                  }
                }
              }
              
              return { reasoning: newReasoning, content: newContent, inThinking, pending };
            });
            return;
          }
          
          setLiveChunkContent({ reasoning: '', content: '', inThinking: false, pending: '' });
          
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
          queryClient.invalidateQueries({ queryKey: ['auditSessions'] });
          queryClient.invalidateQueries({ queryKey: ['auditStatus'] });
          setLiveChunkContent({ reasoning: '', content: '', inThinking: false, pending: '' });
        },
        (err) => {
          console.error('Stream error:', err);
        }
      );
    } else {
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
      <div className="flex items-center justify-between mb-6 shrink-0">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">AIDA Audit Dashboard</h1>
          <p className="text-sm text-muted-foreground">Monitor and control the autonomous auditing agent.</p>
        </div>
        
        <div className="flex items-center gap-2">
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
          onClick={() => setActiveTab('coverage')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${activeTab === 'coverage' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
        >
          <Layers className="w-4 h-4" /> Coverage
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

        {activeTab === 'coverage' && (
          <Card className="h-full flex flex-col border-0 shadow-none bg-transparent">
            <CardContent className="flex-1 overflow-auto p-0">
                <CoverageView />
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
